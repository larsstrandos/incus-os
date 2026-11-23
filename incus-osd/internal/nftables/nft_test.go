package nftables

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lxc/incus-os/incus-osd/api"
)

func TestVXLANRules(t *testing.T) {
	t.Parallel()

	cfg := &api.SystemNetworkConfig{
		Interfaces: []api.SystemNetworkInterface{
			{Name: "mgmt", Roles: []string{"management"}},
			{Name: "uplink0", Roles: []string{"underlay"}},
		},
		VLANs: []api.SystemNetworkVLAN{{Name: "ul100", Roles: []string{"underlay", "storage"}}},
		VXLANs: []api.SystemNetworkVXLAN{
			{Name: "evpn0", Local: "10.255.0.11", VNI: 10400, FirewallSources: []string{"10.255.0.0/24", "10.255.0.12", "fd00::1"}},
			{Name: "blue", Local: "10.255.0.11", Port: 4790, VNI: 10500, FirewallSources: []string{"10.255.0.12"}},
			{Name: "red", Local: "10.255.0.11", Port: 4790, VNI: 10600},
			{Name: "v6", Local: "fd00::11", Port: 4790, VNI: 10700, FirewallSources: []string{"10.255.0.12"}},
		},
	}

	require.Equal(t, [][]string{
		{"udp", "dport", "{4789,4790}", "iifname", "!=", "{_vuplink0,ul100}", "counter", "drop"},
		{"meta", "nfproto", "ipv6", "exthdr", "frag", "exists", "udp", "dport", "{4789,4790}", "counter", "drop"},
		{"ip", "daddr", "10.255.0.11", "udp", "dport", "4789", "@th,96,24", "10400", "ip", "saddr", "!=", "{10.255.0.0/24}", "counter", "drop"},
		{"ip", "daddr", "10.255.0.11", "udp", "dport", "4790", "@th,96,24", "10500", "ip", "saddr", "!=", "{10.255.0.12/32}", "counter", "drop"},
		{"ip6", "daddr", "fd00::11", "udp", "dport", "4790", "@th,96,24", "10700", "counter", "drop"},
		{"ip", "daddr", "10.255.0.11", "udp", "dport", "4789", "@th,96,24", "!=", "{10400}", "counter", "drop"},
		{"ip", "daddr", "10.255.0.11", "udp", "dport", "4790", "@th,96,24", "!=", "{10500,10600}", "counter", "drop"},
		{"ip6", "daddr", "fd00::11", "udp", "dport", "4790", "@th,96,24", "!=", "{10700}", "counter", "drop"},
	}, vxlanRules(cfg))

	// Without underlay interfaces, there are no rules.
	cfg.Interfaces[1].Roles = nil
	cfg.VLANs[0].Roles = nil
	require.Nil(t, vxlanRules(cfg))
}

func TestSourcePrefixes(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"10.0.0.0/16", "192.0.2.1/32"}, sourcePrefixes([]string{"10.0.1.0/24", "10.0.0.0/16", "192.0.2.1", "192.0.2.1/32", "fd00::/64"}, false))
	require.Equal(t, []string{"fd00::/64"}, sourcePrefixes([]string{"10.0.1.0/24", "fd00::/64", "fd00::5"}, true))
}
