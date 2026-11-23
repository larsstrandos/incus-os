package applications

import (
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/lxc/incus-os/incus-osd/api"
)

func birdEVPNTestConfig() (*api.SystemNetworkConfig, *api.ApplicationBirdEVPN) {
	netCfg := &api.SystemNetworkConfig{
		VTEP: &api.SystemNetworkVTEP{Local: "10.214.214.15", FirewallSources: []string{"10.214.214.16", "10.255.21.0/24"}},
		VXLANs: []api.SystemNetworkVXLAN{
			{Name: "blue", VNI: 10100},
			{Name: "red", VNI: 20200},
			{Name: "blue5", VNI: 10500},
			{Name: "l3cust", VNI: 50100, VRF: "cust"},
		},
	}

	evpn := &api.ApplicationBirdEVPN{
		ASN:            4200000105,
		RouteTargetASN: 65000,
		Peers: []api.ApplicationBirdEVPNPeer{
			{Name: "hv6", Address: "10.214.214.16", ASN: 4200000106},
			{Name: "aeos-1", Address: "10.214.214.21", ASN: 65021},
		},
		RouteTargets: []api.ApplicationBirdEVPNRouteTarget{
			{VXLAN: "red", RouteTarget: "65001:200"},
		},
		BFD:          true,
		ReceiveLimit: 20000,
	}

	return netCfg, evpn
}

func TestBirdEVPNConfig(t *testing.T) {
	t.Parallel()

	netCfg, evpn := birdEVPNTestConfig()

	cfg, err := birdEVPNConfig(netCfg, evpn)
	require.NoError(t, err)

	// Keep a copy for "bird -p" when asked to.
	path := os.Getenv("BIRD_EVPN_DUMP")
	if path != "" {
		full, err := birdFullConfig("", netCfg, evpn)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte(full), 0o600))
	}

	require.Contains(t, cfg, "evpn table incusos_evpn;\n")

	// A bridge and an EVPN instance per VXLAN, with automatic and set route targets.
	require.Contains(t, cfg, `protocol evpn incusos_evpn_blue {
  eth { table incusos_eth_blue; };
  evpn { table incusos_evpn; };
  rd 10.214.214.15:10100;
  route target (rt, 65000, 10100);
  encapsulation vxlan { tunnel device "_xblue"; router address 10.214.214.15; };
  vni 10100;
}
`)
	require.Contains(t, cfg, "  rd 10.214.214.15:20200;\n  route target (rt, 65001, 200);\n")
	require.NotContains(t, cfg, "vlan filtering")

	require.Contains(t, cfg, `protocol evpn incusos_evpn_blue5 {
  eth { table incusos_eth_blue5; };
  evpn { table incusos_evpn; };
  rd 10.214.214.15:10500;
  route target (rt, 65000, 10500);
  encapsulation vxlan { tunnel device "_xblue5"; router address 10.214.214.15; };
  vni 10500;
}
`)
	require.Contains(t, cfg, `import filter { if ifname = "_xblue5" then reject; accept; };`)

	// The layer 3 VNI only gets a comment.
	require.Contains(t, cfg, "# vxlan l3cust: VNI 50100 in VRF cust")
	require.NotContains(t, cfg, "incusos_evpn_l3cust")

	// The tunnel endpoints are the firewall sources.
	require.Contains(t, cfg, "  return a ~ 10.214.214.16/32 || a ~ 10.255.21.0/24;\n")
	require.Contains(t, cfg, "  if !incusos_is_vtep(bgp_next_hop) then reject;\n")

	// The sessions.
	require.Contains(t, cfg, "  local 10.214.214.15 as 4200000105;\n  multihop;\n  bfd on;\n")
	require.Contains(t, cfg, "    receive limit 20000 action block;\n")
	require.Contains(t, cfg, "protocol bgp incusos_evpn_hv6 from incusos_evpn_peer { neighbor 10.214.214.16 as 4200000106; }\n")
	require.Contains(t, cfg, "protocol bgp incusos_evpn_aeos_1 from incusos_evpn_peer { neighbor 10.214.214.21 as 65021; }\n")

	// Without evpn settings, nothing is generated.
	cfg, err = birdEVPNConfig(netCfg, nil)
	require.NoError(t, err)
	require.Empty(t, cfg)
}

func TestBirdFullConfig(t *testing.T) {
	t.Parallel()

	netCfg, evpn := birdEVPNTestConfig()

	// The raw configuration comes first, the generated part after it.
	full, err := birdFullConfig("router id 10.0.0.1;\nprotocol device { }\n", netCfg, evpn)
	require.NoError(t, err)
	require.Regexp(t, `^router id 10\.0\.0\.1;\nprotocol device \{ \}\n\n# ---- BGP EVPN`, full)
	require.Equal(t, "router id 10.0.0.1;\nprotocol device { }\n", birdRawConfig(full))

	// Without a raw configuration, a minimal one carries the EVPN part.
	full, err = birdFullConfig("", netCfg, evpn)
	require.NoError(t, err)
	require.Contains(t, full, "router id 10.214.214.15;\nprotocol device { }\n")
	require.Empty(t, birdRawConfig(full))

	// Without EVPN, the raw configuration is used as is.
	full, err = birdFullConfig("router id 10.0.0.1;\n", netCfg, nil)
	require.NoError(t, err)
	require.Equal(t, "router id 10.0.0.1;\n", full)
}

func TestBirdEVPNConfigErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		change func(*api.SystemNetworkConfig, *api.ApplicationBirdEVPN)
		err    string
	}{
		{"no asn", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.ASN = 0 }, "evpn needs an asn"},
		{"no vxlans", func(n *api.SystemNetworkConfig, _ *api.ApplicationBirdEVPN) { n.VXLANs = nil }, "evpn needs vxlans in the network configuration"},
		{"two locals", func(n *api.SystemNetworkConfig, _ *api.ApplicationBirdEVPN) { n.VXLANs[1].Local = "10.214.214.99" }, "evpn needs all vxlans on one local address, vxlan red uses 10.214.214.99 and not 10.214.214.15"},
		{"ipv6 vtep", func(n *api.SystemNetworkConfig, _ *api.ApplicationBirdEVPN) { n.VTEP.Local = "fd00::15" }, `evpn needs an IPv4 vtep address, not "fd00::15"`},
		{"route target for unknown vxlan", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.RouteTargets[0].VXLAN = "nope" }, `evpn route target for vxlan "nope": the vxlan doesn't exist`},
		{"route target for a vrf vxlan", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.RouteTargets[0].VXLAN = "l3cust" }, `evpn route target for vxlan "l3cust": a vxlan in a vrf gets no evpn instance`},
		{"route target set twice", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) {
			e.RouteTargets = append(e.RouteTargets, api.ApplicationBirdEVPNRouteTarget{VXLAN: "red", RouteTarget: "65001:201"})
		}, `evpn route target for vxlan "red": set more than once`},
		{"vni used twice", func(n *api.SystemNetworkConfig, _ *api.ApplicationBirdEVPN) {
			n.VXLANs[1].VNI = 10100
			n.VXLANs[1].Port = 4790
		}, "vxlan red: vni 10100 is already used by vxlan blue"},
		{"vni too large for the rd", func(n *api.SystemNetworkConfig, _ *api.ApplicationBirdEVPN) { n.VXLANs[1].VNI = 70000 }, "vxlan red: vni 70000 doesn't fit the route distinguisher <vtep>:<vni>, use a vni up to 65535"},
		{"number too large for a 4 byte rt asn", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) {
			e.RouteTargets[0].RouteTarget = "4200000000:70000"
		}, `evpn route target for vxlan "red": route target "4200000000:70000" has an invalid number`},
		{"bad route target", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.RouteTargets[0].RouteTarget = "65001" }, `evpn route target for vxlan "red": route target "65001" isn't <asn>:<number>`},
		{"peer without name", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.Peers[0].Name = "" }, "evpn peer without a name"},
		{"peer name twice", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.Peers[1].Name = "hv6" }, `evpn peer "hv6": the name is already used`},
		{"peer address", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.Peers[0].Address = "hv6" }, `evpn peer "hv6": invalid address "hv6"`},
		{"peer asn", func(_ *api.SystemNetworkConfig, e *api.ApplicationBirdEVPN) { e.Peers[0].ASN = 0 }, `evpn peer "hv6" needs an asn`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			netCfg, evpn := birdEVPNTestConfig()
			test.change(netCfg, evpn)

			_, err := birdEVPNConfig(netCfg, evpn)
			require.EqualError(t, err, test.err)
		})
	}
}

func TestChangedBirdEVPNProtocols(t *testing.T) {
	t.Parallel()

	netCfg, evpn := birdEVPNTestConfig()

	oldCfg, err := birdFullConfig("router id 10.0.0.1;\n", netCfg, evpn)
	require.NoError(t, err)

	require.Equal(t, []string{"incusos_evpn_blue", "incusos_evpn_blue5", "incusos_evpn_red"}, slices.Sorted(maps.Keys(birdEVPNProtocols(oldCfg))))
	require.Empty(t, changedBirdEVPNProtocols(oldCfg, oldCfg))

	// A new route target on red, a new VXLAN green and a new peer: only red changed.
	evpn.RouteTargets = nil
	evpn.Peers = append(evpn.Peers, api.ApplicationBirdEVPNPeer{Name: "hv7", Address: "10.214.214.17", ASN: 4200000107})
	netCfg.VXLANs = append(netCfg.VXLANs, api.SystemNetworkVXLAN{Name: "green", VNI: 10300})

	newCfg, err := birdFullConfig("router id 10.0.0.1;\n", netCfg, evpn)
	require.NoError(t, err)
	require.Equal(t, []string{"incusos_evpn_red"}, changedBirdEVPNProtocols(oldCfg, newCfg))

	// Nothing to restart without an earlier generated configuration.
	require.Empty(t, changedBirdEVPNProtocols("", newCfg))
}
