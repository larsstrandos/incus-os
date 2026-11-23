package api

// ApplicationBirdConfig represents additional configuration for the BIRD application.
type ApplicationBirdConfig struct {
	ApplicationConfig

	// Raw bird.conf contents, validated with "bird -p" before being applied.
	Config string `json:"config" yaml:"config"`

	// BGP EVPN for the VXLANs of the network configuration. IncusOS generates the BIRD configuration for them
	// and appends it to the raw configuration.
	EVPN *ApplicationBirdEVPN `json:"evpn,omitempty" yaml:"evpn,omitempty"`
}

// ApplicationBirdEVPN contains the BGP EVPN settings of the BIRD application. The local VXLAN tunnel endpoint,
// the bridges and their VNIs come from the network configuration (vtep and vxlans).
type ApplicationBirdEVPN struct {
	// Local AS number of the EVPN sessions.
	ASN uint32 `json:"asn" yaml:"asn"`

	// AS number of the automatic route targets (<asn>:<vni>), which must be the same on all hosts. Defaults to
	// the local AS number.
	RouteTargetASN uint32 `json:"route_target_asn,omitempty" yaml:"route_target_asn,omitempty"`

	// EVPN peers: the other hosts, route reflectors or switches.
	Peers []ApplicationBirdEVPNPeer `json:"peers,omitempty" yaml:"peers,omitempty"`

	// Route targets other than the automatic <route_target_asn>:<vni>, by VXLAN.
	RouteTargets []ApplicationBirdEVPNRouteTarget `json:"route_targets,omitempty" yaml:"route_targets,omitempty"`

	// Use BFD on the EVPN sessions. The raw configuration must have a bfd protocol accepting multihop sessions.
	BFD bool `json:"bfd,omitempty" yaml:"bfd,omitempty"`

	// Maximum number of EVPN routes accepted from a peer, unlimited if not set.
	ReceiveLimit int `json:"receive_limit,omitempty" yaml:"receive_limit,omitempty"`
}

// ApplicationBirdEVPNPeer represents an EVPN peer.
type ApplicationBirdEVPNPeer struct {
	// Name of the peer, used in the BIRD protocol name.
	Name string `json:"name" yaml:"name"`

	// Address of the peer.
	Address string `json:"address" yaml:"address"`

	// AS number of the peer.
	ASN uint32 `json:"asn" yaml:"asn"`
}

// ApplicationBirdEVPNRouteTarget sets the route target of a VXLAN.
type ApplicationBirdEVPNRouteTarget struct {
	// Name of the VXLAN.
	VXLAN string `json:"vxlan" yaml:"vxlan"`

	// Route target (<asn>:<number>).
	RouteTarget string `json:"route_target" yaml:"route_target"`
}

// ApplicationBird represents the state and configuration of the BIRD application.
type ApplicationBird struct {
	State ApplicationState `json:"state" yaml:"state"`

	Config ApplicationBirdConfig `json:"config" yaml:"config"`
}
