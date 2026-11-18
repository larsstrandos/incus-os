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
* When the application is installed, TCP port 179 (BGP) and UDP ports 3784 and 3785 (BFD) are allowed on interfaces
  that have firewall rules configured.
* The host side of a `routed` NIC has no address. Routes whose next hop is such an instance should be exported to the
  kernel with `onlink = true`, otherwise BIRD doesn't recognize them when scanning the kernel table and keeps re-adding them.

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
