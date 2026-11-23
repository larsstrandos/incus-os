# Metrics

IncusOS exposes metrics about itself in the Prometheus/OpenMetrics text format at
`/1.0/metrics` (`/os/1.0/metrics` when accessed through Incus).

```
incus query /os/1.0/metrics
```

All metric names start with `incusos_`, so they can be combined with the metrics of Incus and
of the bundled node-exporter without conflicts.

| Metric                                        | Description                                                            |
| --------------------------------------------- | ---------------------------------------------------------------------- |
| `incusos_info`                                | Always 1, with the OS name and running release as labels.              |
| `incusos_update_needs_reboot`                 | 1 if an update has been applied that requires a reboot.                |
| `incusos_update_next_release_info`            | Always 1, with the next release as label, while it is not running yet. |
| `incusos_update_last_check_timestamp_seconds` | Time of the last update check.                                         |
| `incusos_security_secure_boot_enabled`        | 1 if Secure Boot is enabled.                                           |
| `incusos_security_swtpm_in_use`               | 1 if IncusOS uses its own software TPM because no TPM is available.    |
| `incusos_application_info`                    | Always 1, one per installed application, with name and version.        |
| `incusos_go_*`, `incusos_process_*`           | Go runtime and process metrics of the IncusOS management daemon.       |

Hardware and SMART metrics are provided by node-exporter instead.

For example, the following Prometheus alerting rule fires when a host has a pending reboot:

```yaml
- alert: IncusOSNeedsReboot
  expr: incusos_update_needs_reboot == 1
  for: 1d
```
