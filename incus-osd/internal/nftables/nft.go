package nftables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/lxc/incus/v7/shared/subprocess"

	"github.com/lxc/incus-os/incus-osd/api"
)

// SetupChains creates the initial system-wide chains.
func SetupChains(ctx context.Context) error {
	// Ensure we have an inet table.
	_, err := subprocess.RunCommandContext(ctx, "nft", "add", "table", "inet", "incus-osd")
	if err != nil {
		return err
	}

	// Ensure we have an input filtering chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "chain", "inet", "incus-osd", "input", "{ type filter hook input priority 0 ; policy accept ; }")
	if err != nil {
		return err
	}

	// Ensure we have a VXLAN filtering chain, ahead of the input chain and its user rules.
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "chain", "inet", "incus-osd", "vxlan-underlay", "{ type filter hook input priority -10 ; policy accept ; }")
	if err != nil {
		return err
	}

	// Ensure we have a forward filtering chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "chain", "inet", "incus-osd", "forward", "{ type filter hook forward priority 0 ; policy accept ; }")
	if err != nil {
		return err
	}

	// Ensure we have a bridge table.
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "table", "bridge", "incus-osd")
	if err != nil {
		return err
	}

	// Ensure we have a MAC filtering chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "chain", "bridge", "incus-osd", "mac-filters", "{ type filter hook postrouting priority 0 ; policy accept ; }")
	if err != nil {
		return err
	}

	// Ensure we have a conntrack bypass chain (hooked ahead of nf_conntrack_bridge at -200).
	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "chain", "bridge", "incus-osd", "conntrack-bypass", "{ type filter hook prerouting priority -300 ; policy accept ; }")
	if err != nil {
		return err
	}

	return nil
}

// ApplyNotrackFilters excludes traffic entering the managed bridges from bridge conntrack.
// When nf_conntrack_bridge is active (loaded by Incus for bridge NIC ACLs), traffic already tracked and
// NATed at the IP layer would otherwise be re-tracked with its post-NAT tuple on entering the bridge
// through the host-side veth, then dropped on conntrack insertion clash at bridge postrouting.
// Similarly, inbound traffic entering through the physical port would get confirmed at bridge
// postrouting with its pre-NAT tuple, preventing the IP layer from ever applying DNAT (forwards).
func ApplyNotrackFilters(ctx context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Make sure we have the expected chains.
	err := SetupChains(ctx)
	if err != nil {
		return err
	}

	// Empty the chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "flush", "chain", "bridge", "incus-osd", "conntrack-bypass")
	if err != nil {
		return err
	}

	// Get the list of bridge ports (bridge-side veth and outside-facing device) for the managed bridges.
	ifaces := []string{}

	for _, iface := range networkCfg.Interfaces {
		if iface.Hwaddr == "" {
			continue
		}

		strippedHwaddr := strings.ToLower(strings.ReplaceAll(iface.Hwaddr, ":", ""))
		ifaces = append(ifaces, "_i"+strippedHwaddr, "_p"+strippedHwaddr)
	}

	for _, iface := range networkCfg.Bonds {
		hwaddr := iface.Hwaddr
		if hwaddr == "" && len(iface.Members) > 0 {
			hwaddr = iface.Members[0]
		}

		if hwaddr == "" {
			continue
		}

		ifaces = append(ifaces, "_i"+strings.ToLower(strings.ReplaceAll(hwaddr, ":", "")), "_b"+iface.Name)
	}

	for _, vxlan := range networkCfg.VXLANs {
		ifaces = append(ifaces, "_x"+vxlan.Name)
	}

	if len(ifaces) == 0 {
		return nil
	}

	// Disable connection tracking for traffic entering the bridge.
	set := "{" + strings.Join(ifaces, ",") + "}"

	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "rule", "bridge", "incus-osd", "conntrack-bypass", "iifname", set, "notrack")
	if err != nil {
		return err
	}

	return nil
}

// ApplyHwaddrFilters ensures that all interfaces with the StrictHwaddr flag set get a suitable MAC filter in place.
func ApplyHwaddrFilters(ctx context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Make sure we have the expected chains.
	err := SetupChains(ctx)
	if err != nil {
		return err
	}

	// Empty the chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "flush", "chain", "bridge", "incus-osd", "mac-filters")
	if err != nil {
		return err
	}

	// Apply the filters.
	for _, iface := range networkCfg.Interfaces {
		if !iface.StrictHwaddr {
			continue
		}

		underlyingDevice := "_p" + strings.ToLower(strings.ReplaceAll(iface.Hwaddr, ":", ""))

		_, err = subprocess.RunCommandContext(ctx, "nft", "add", "rule", "bridge", "incus-osd", "mac-filters", "oifname", underlyingDevice, "ether", "saddr", "!=", iface.Hwaddr, "drop")
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyForwardFilters blocks routing between IncusOS-managed interfaces.
// Forwarding involving other interfaces (Incus managed networks, Tailscale, Netbird, ...) is unaffected.
func ApplyForwardFilters(ctx context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Make sure we have the expected chains.
	err := SetupChains(ctx)
	if err != nil {
		return err
	}

	// Empty the chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "flush", "chain", "inet", "incus-osd", "forward")
	if err != nil {
		return err
	}

	// Get the list of layer 3 interfaces managed by IncusOS.
	ifaces := []string{}

	for _, iface := range networkCfg.Interfaces {
		ifaces = append(ifaces, "_v"+iface.Name)
	}

	for _, iface := range networkCfg.Bonds {
		ifaces = append(ifaces, "_v"+iface.Name)
	}

	for _, iface := range networkCfg.VLANs {
		ifaces = append(ifaces, iface.Name)
	}

	for _, iface := range networkCfg.Wireguard {
		ifaces = append(ifaces, iface.Name)
	}

	if len(ifaces) == 0 {
		return nil
	}

	// Drop any traffic being routed from one IncusOS-managed interface to another.
	set := "{" + strings.Join(ifaces, ",") + "}"

	_, err = subprocess.RunCommandContext(ctx, "nft", "add", "rule", "inet", "incus-osd", "forward", "iifname", set, "oifname", set, "drop")
	if err != nil {
		return err
	}

	// Traffic received in a VRF has the VRF device as its input interface, the member being the slave input interface.
	if len(networkCfg.VRFs) > 0 {
		_, err = subprocess.RunCommandContext(ctx, "nft", "add", "rule", "inet", "incus-osd", "forward", "meta", "sdifname", set, "oifname", set, "drop")
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyInputFilters applies the input firewall rules.
func ApplyInputFilters(ctx context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Make sure we have the expected chains.
	err := SetupChains(ctx)
	if err != nil {
		return err
	}

	// Empty the chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "flush", "chain", "inet", "incus-osd", "input")
	if err != nil {
		return err
	}

	// Apply the filters.
	applyFirewall := func(iface string, vrf string, firewallRules []api.SystemNetworkFirewallRule) error {
		// Baseline rules.
		rules := [][]string{
			{"ct", "state", "established,related", "accept"},
			{"ct", "state", "invalid", "drop"},
			{"ip", "protocol", "icmp", "accept"},
			{"icmp", "type", "{echo-request,destination-unreachable,time-exceeded,parameter-problem}", "accept"},
			{"icmpv6", "type", "{echo-request,nd-neighbor-solicit,nd-neighbor-advert,nd-router-solicit,nd-router-advert,mld-listener-query}", "accept"},
		}

		// Allow VXLAN from the configured sources, VXLAN devices only listen in the default VRF.
		if vrf == "" {
			for _, vxlan := range networkCfg.EffectiveVXLANs() {
				port := vxlan.Port
				if port == 0 {
					port = 4789
				}

				for _, source := range vxlan.FirewallSources {
					family := "ip"
					if strings.Contains(source, ":") {
						family = "ip6"
					}

					rules = append(rules, []string{family, "saddr", source, "udp", "dport", strconv.Itoa(port), "accept"})
				}
			}
		}

		// Add the user rules.
		for _, firewallRule := range firewallRules {
			rule := []string{}

			if firewallRule.Source != "" {
				var ip net.IP

				if strings.Contains(firewallRule.Source, "/") {
					var err error

					ip, _, err = net.ParseCIDR(firewallRule.Source)
					if err != nil {
						return err
					}
				} else {
					ip = net.ParseIP(firewallRule.Source)
				}

				if ip == nil {
					return fmt.Errorf("bad source %q", firewallRule.Source)
				}

				if ip.To4() == nil {
					rule = append(rule, "ip6", "saddr", firewallRule.Source)
				} else {
					rule = append(rule, "ip", "saddr", firewallRule.Source)
				}
			}

			if firewallRule.Protocol != "" {
				rule = append(rule, firewallRule.Protocol, "dport", strconv.Itoa(firewallRule.Port))
			}

			rule = append(rule, firewallRule.Action)
			rules = append(rules, rule)
		}

		// Apply the interface rules.
		matches := [][]string{{"iifname", iface}}

		// Traffic to the host received on a VRF member has the VRF device as its input interface,
		// except for neighbor discovery.
		if vrf != "" {
			matches = append(matches, []string{"iifname", vrf, "meta", "sdifname", iface})
		}

		for _, match := range matches {
			args := append([]string{"add", "rule", "inet", "incus-osd", "input"}, match...)

			for _, rule := range rules {
				_, err = subprocess.RunCommandContext(ctx, "nft", append(slices.Clone(args), rule...)...)
				if err != nil {
					return err
				}
			}
		}

		return nil
	}

	for _, iface := range networkCfg.Interfaces {
		if len(iface.FirewallRules) == 0 {
			continue
		}

		err := applyFirewall("_v"+iface.Name, iface.VRF, iface.FirewallRules)
		if err != nil {
			return err
		}
	}

	for _, iface := range networkCfg.Bonds {
		if len(iface.FirewallRules) == 0 {
			continue
		}

		err := applyFirewall("_v"+iface.Name, iface.VRF, iface.FirewallRules)
		if err != nil {
			return err
		}
	}

	for _, iface := range networkCfg.VLANs {
		if len(iface.FirewallRules) == 0 {
			continue
		}

		err := applyFirewall(iface.Name, iface.VRF, iface.FirewallRules)
		if err != nil {
			return err
		}
	}

	for _, iface := range networkCfg.Wireguard {
		if len(iface.FirewallRules) == 0 {
			continue
		}

		err := applyFirewall(iface.Name, "", iface.FirewallRules)
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyVXLANFilters keeps VXLAN traffic on the underlay when the host has interfaces with the underlay role.
func ApplyVXLANFilters(ctx context.Context, networkCfg *api.SystemNetworkConfig) error {
	// Make sure we have the expected chains.
	err := SetupChains(ctx)
	if err != nil {
		return err
	}

	// Empty the chain.
	_, err = subprocess.RunCommandContext(ctx, "nft", "flush", "chain", "inet", "incus-osd", "vxlan-underlay")
	if err != nil {
		return err
	}

	for _, rule := range vxlanRules(networkCfg) {
		_, err = subprocess.RunCommandContext(ctx, "nft", append([]string{"add", "rule", "inet", "incus-osd", "vxlan-underlay"}, rule...)...)
		if err != nil {
			return err
		}
	}

	return nil
}

// vxlanRules returns the rules of the vxlan-underlay chain. With underlay interfaces, VXLAN traffic is dropped unless it
// arrives on one of them, from the firewall sources of the VXLAN and, for single VNI bridges, with a configured VNI.
// The input hook runs after IPv4 reassembly, so the VNI of a fragmented packet is checked too. IPv6 fragments
// aren't reassembled yet at that point and VXLAN must not be fragmented, so they are dropped.
//
// The VNI is matched as raw payload (vxlanVNI), as the "vxlan vni" expression of nftables doesn't match received
// packets in the input hook.
func vxlanRules(networkCfg *api.SystemNetworkConfig) [][]string {
	underlay := []string{}

	for _, iface := range networkCfg.Interfaces {
		if slices.Contains(iface.Roles, api.SystemNetworkInterfaceRoleUnderlay) {
			underlay = append(underlay, "_v"+iface.Name)
		}
	}

	for _, iface := range networkCfg.Bonds {
		if slices.Contains(iface.Roles, api.SystemNetworkInterfaceRoleUnderlay) {
			underlay = append(underlay, "_v"+iface.Name)
		}
	}

	for _, iface := range networkCfg.VLANs {
		if slices.Contains(iface.Roles, api.SystemNetworkInterfaceRoleUnderlay) {
			underlay = append(underlay, iface.Name)
		}
	}

	for _, iface := range networkCfg.Wireguard {
		if slices.Contains(iface.Roles, api.SystemNetworkInterfaceRoleUnderlay) {
			underlay = append(underlay, iface.Name)
		}
	}

	vxlans := networkCfg.EffectiveVXLANs()
	if len(underlay) == 0 || len(vxlans) == 0 {
		return nil
	}

	ports := []string{}

	for _, vxlan := range vxlans {
		port := strconv.Itoa(vxlanPort(vxlan))
		if !slices.Contains(ports, port) {
			ports = append(ports, port)
		}
	}

	rules := [][]string{
		{"udp", "dport", nftSet(ports), "iifname", "!=", nftSet(underlay), "counter", "drop"},
		{"meta", "nfproto", "ipv6", "exthdr", "frag", "exists", "udp", "dport", nftSet(ports), "counter", "drop"},
	}

	// The VNIs of the VXLANs, by local address and port.
	endpoints := []string{}
	endpointVNIs := map[string][]string{}

	for _, vxlan := range vxlans {
		family := "ip"
		if strings.Contains(vxlan.Local, ":") {
			family = "ip6"
		}

		match := []string{family, "daddr", vxlan.Local, "udp", "dport", strconv.Itoa(vxlanPort(vxlan))}

		endpoint := strings.Join(match, " ")
		if !slices.Contains(endpoints, endpoint) {
			endpoints = append(endpoints, endpoint)
		}

		endpointVNIs[endpoint] = append(endpointVNIs[endpoint], strconv.Itoa(vxlan.VNI))
		match = append(match, vxlanVNI, strconv.Itoa(vxlan.VNI))

		if len(vxlan.FirewallSources) == 0 {
			continue
		}

		sources := sourcePrefixes(vxlan.FirewallSources, family == "ip6")
		if len(sources) == 0 {
			rules = append(rules, append(slices.Clone(match), "counter", "drop"))

			continue
		}

		rules = append(rules, append(slices.Clone(match), family, "saddr", "!=", nftSet(sources), "counter", "drop"))
	}

	for _, endpoint := range endpoints {
		match := strings.Split(endpoint, " ")
		rules = append(rules, append(match, vxlanVNI, "!=", nftSet(endpointVNIs[endpoint]), "counter", "drop"))
	}

	return rules
}

// vxlanVNI matches the 24 bit VNI of a VXLAN packet, after the 8 bytes of UDP header and the 4 bytes of VXLAN flags.
const vxlanVNI = "@th,96,24"

// vxlanPort returns the UDP port of a VXLAN.
func vxlanPort(vxlan api.SystemNetworkVXLAN) int {
	if vxlan.Port == 0 {
		return 4789
	}

	return vxlan.Port
}

// sourcePrefixes returns the sources of one address family as prefixes, leaving out those within another source,
// as nftables refuses overlapping intervals in a set.
func sourcePrefixes(sources []string, ipv6 bool) []string {
	prefixes := []netip.Prefix{}

	for _, source := range sources {
		prefix, err := netip.ParsePrefix(source)
		if err != nil {
			addr, err := netip.ParseAddr(source)
			if err != nil {
				continue
			}

			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}

		if prefix.Addr().Is6() != ipv6 {
			continue
		}

		prefixes = append(prefixes, prefix.Masked())
	}

	ret := []string{}

	for i, prefix := range prefixes {
		covered := slices.ContainsFunc(prefixes[:i], func(other netip.Prefix) bool {
			return other.Bits() <= prefix.Bits() && other.Contains(prefix.Addr())
		})

		covered = covered || slices.ContainsFunc(prefixes[i+1:], func(other netip.Prefix) bool {
			return other.Bits() < prefix.Bits() && other.Contains(prefix.Addr())
		})

		if !covered {
			ret = append(ret, prefix.String())
		}
	}

	return ret
}

// nftSet returns an anonymous nftables set of the given elements.
func nftSet(elements []string) string {
	return "{" + strings.Join(elements, ",") + "}"
}
