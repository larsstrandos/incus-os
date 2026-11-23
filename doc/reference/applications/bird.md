# BIRD

The BIRD (`bird`) application runs the [BIRD Internet Routing Daemon](https://bird.network.cz/) on the host.
BIRD is installed from the [CZ.NIC Labs package repository](https://pkg.labs.nic.cz/doc/?project=bird) (tagged releases only).
It allows an IncusOS system to take part in a routed network, for example running BGP to top-of-rack switches,
announcing routes for instances using `routed` NICs and importing routes from the network.

## Configuration

BIRD is configured through a raw `bird.conf`, set through the application's `config` field.
The current configuration is shown with `show` and changed with `edit`:

    incus admin os application show bird
    incus admin os application edit bird

```yaml
config:
  config: |
    router id 192.0.2.1;
    protocol device {}
    ...
```

The configuration is validated with `bird -p` before being applied. A valid configuration is then written to
`/var/lib/bird/bird.conf` and loaded with `birdc configure`, so existing sessions aren't reset unless the configuration requires it.
Setting an empty configuration stops the daemon.

## Networking

* Routes are installed with the `bird` routing protocol. The application ships a `systemd-networkd` configuration
  setting `ManageForeignRoutes=no` so that network reconfiguration doesn't remove them.
* When the application is installed, TCP port 179 (BGP) and UDP ports 3784, 3785 and 4784 (single hop and multihop
  BFD) are allowed on interfaces that have firewall rules configured.
* The host side of a `routed` NIC has no address. Routes whose next hop is such an instance should be exported to the
  kernel with `onlink = true`, otherwise BIRD doesn't recognize them when scanning the kernel table and keeps re-adding them.

## BGP EVPN

BIRD can run BGP EVPN for the VXLAN bridges of the [network configuration](../system/network.md#vxlans): it learns the
MAC addresses on the bridges, advertises them to the other hosts and installs theirs in the forwarding tables of the
VXLAN ports. IncusOS generates the BIRD configuration for this from the network configuration and the application's
`evpn` settings, and appends it to the raw configuration:

```yaml
config:
  config: |
    router id 10.255.0.11;
    protocol device {}
    # The routing towards the other VTEPs: fabric, kernel, filters, ...
  evpn:
    asn: 4200000101
    route_target_asn: 65000
    peers:
      - {name: hv2, address: 10.255.0.12, asn: 4200000102}
    route_targets:
      - {vxlan: red, route_target: "65001:200"}
    receive_limit: 20000
```

The `evpn` settings consist of:

* `asn`: The local AS number of the EVPN sessions.

* `route_target_asn`: Optionally, the AS number of the automatic route targets `<asn>:<vni>` (defaults to `asn`). It
  must be the same on all hosts, so set it when the hosts have their own AS numbers.

* `peers`: The EVPN peers (other hosts, route reflectors or switches), each with a `name`, an `address` and an `asn`.

* `route_targets`: Optionally, route targets other than the automatic one, each with the `vxlan` and its `route_target`
  (`<asn>:<number>`), for example to match the route target a switch uses for that VNI.

* `bfd`: Optionally, use BFD on the EVPN sessions. The raw configuration needs a `bfd` protocol with a `multihop`
  block.

* `receive_limit`: Optionally, the maximum number of EVPN routes accepted from a peer.

From the network configuration, the `vtep` address is the source of the EVPN sessions and the address of the local
VXLAN tunnel endpoint, which must be IPv4. Each VXLAN bridge gets its own EVPN instance with the route distinguisher
`<vtep>:<vni>`, so its VNI can be at most 65535. A VXLAN bridge in a VRF, a layer 3 VNI, gets no EVPN instance, as BIRD can't handle EVPN type 5 routes yet. Routes are
only accepted when their tunnel endpoint is within the `firewall_sources` of the VXLANs.

The raw configuration is responsible for reaching the other VTEPs: the EVPN sessions are multihop and their next hops
have to resolve in the main routing table, for example through BGP routes from the fabric. Without a raw configuration,
IncusOS uses a minimal one with a router ID, the `device` protocol and the `direct` protocol, which is enough when the
VTEPs share a network. The generated names start with `incusos_`, so the raw configuration shouldn't use that prefix.

When the network configuration changes, IncusOS regenerates the EVPN part and reloads BIRD. A network configuration
that doesn't fit the `evpn` settings, for example one that removes a VXLAN with a route target set, is rejected.

## Running `birdc` commands

Read-only `birdc` commands can be run through the application's debug endpoint, which returns the command's output:

    incus query -X POST /os/1.0/applications/bird/:debug --data '{"action":"birdc","config":{"command":"show protocols"}}' | jq -r .

`birdc` runs in restricted mode, so only `show` commands are allowed. For example:

| Command                                     | Shows                                       |
| ------------------------------------------- | ------------------------------------------- |
| `show protocols`                            | Sessions and their state                    |
| `show protocols all <name>`                 | Details of one session                      |
| `show bfd sessions`                         | BFD sessions                                |
| `show route table master6`                  | Routes in a table                           |
| `show route for <prefix> all`               | All paths and attributes for a prefix       |
| `show route export <protocol>`              | Routes sent to a peer                       |

Use the application configuration API to change the configuration, which triggers `birdc configure`.
