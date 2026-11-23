package metrics

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

// Prefix is added to every metric name so the IncusOS metrics can be combined with the
// Incus and node-exporter ones (which also expose go_* and process_* metrics) without conflicts.
const Prefix = "incusos_"

// Application holds the details of an installed application that are exported as metrics.
type Application struct {
	Name    string
	Version string
}

// ApplicationsFunc returns the list of installed applications.
type ApplicationsFunc func(ctx context.Context) ([]Application, error)

var (
	descInfo = prometheus.NewDesc(
		Prefix+"info",
		"Information about the running IncusOS release.",
		[]string{"name", "version"}, nil,
	)

	descUpdateNeedsReboot = prometheus.NewDesc(
		Prefix+"update_needs_reboot",
		"Whether an update has been applied that requires a reboot (1) or not (0).",
		nil, nil,
	)

	descUpdateNextRelease = prometheus.NewDesc(
		Prefix+"update_next_release_info",
		"Information about the IncusOS release that will be used on next boot, if it differs from the running one.",
		[]string{"version"}, nil,
	)

	descUpdateLastCheck = prometheus.NewDesc(
		Prefix+"update_last_check_timestamp_seconds",
		"Time of the last update check, in seconds since the Unix epoch.",
		nil, nil,
	)

	descSecureBootEnabled = prometheus.NewDesc(
		Prefix+"security_secure_boot_enabled",
		"Whether Secure Boot is enabled (1) or not (0).",
		nil, nil,
	)

	descSWTPM = prometheus.NewDesc(
		Prefix+"security_swtpm_in_use",
		"Whether IncusOS uses its own software TPM because no TPM is available (1) or not (0).",
		nil, nil,
	)

	descApplicationInfo = prometheus.NewDesc(
		Prefix+"application_info",
		"Information about an installed application.",
		[]string{"name", "version"}, nil,
	)
)

// collectTimeout limits how long a scrape waits for the list of installed applications.
const collectTimeout = 5 * time.Second

// osCollector collects metrics from the IncusOS state and the installed applications.
// A new one is made for each scrape, with the applications listed for that scrape.
type osCollector struct {
	state        *state.State
	applications []Application
}

// Describe implements prometheus.Collector.
func (*osCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range []*prometheus.Desc{
		descInfo,
		descUpdateNeedsReboot,
		descUpdateNextRelease,
		descUpdateLastCheck,
		descSecureBootEnabled,
		descSWTPM,
		descApplicationInfo,
	} {
		ch <- desc
	}
}

// Collect implements prometheus.Collector.
func (c *osCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.state

	for _, m := range []prometheus.Metric{
		prometheus.MustNewConstMetric(descInfo, prometheus.GaugeValue, 1, s.OS.Name, s.OS.RunningRelease),
		prometheus.MustNewConstMetric(descUpdateNeedsReboot, prometheus.GaugeValue, BoolToFloat(s.System.Update.State.NeedsReboot)),
		prometheus.MustNewConstMetric(descSecureBootEnabled, prometheus.GaugeValue, BoolToFloat(!s.SecureBootDisabled)),
		prometheus.MustNewConstMetric(descSWTPM, prometheus.GaugeValue, BoolToFloat(s.UsingSWTPM)),
	} {
		ch <- m
	}

	if s.OS.NextRelease != "" && s.OS.NextRelease != s.OS.RunningRelease {
		ch <- prometheus.MustNewConstMetric(descUpdateNextRelease, prometheus.GaugeValue, 1, s.OS.NextRelease)
	}

	if !s.System.Update.State.LastCheck.IsZero() {
		ch <- prometheus.MustNewConstMetric(descUpdateLastCheck, prometheus.GaugeValue, float64(s.System.Update.State.LastCheck.Unix()))
	}

	for _, app := range c.applications {
		ch <- prometheus.MustNewConstMetric(descApplicationInfo, prometheus.GaugeValue, 1, app.Name, app.Version)
	}
}

// handler serves the IncusOS metrics.
type handler struct {
	base         *prometheus.Registry
	state        *state.State
	applications ApplicationsFunc
}

// NewHandler returns an HTTP handler serving the Go runtime, process and IncusOS metrics.
// The installed applications are listed once per scrape, within the request's context.
func NewHandler(s *state.State, applications ApplicationsFunc) (http.Handler, error) {
	base := prometheus.NewRegistry()
	wrapped := prometheus.WrapRegistererWithPrefix(Prefix, base)

	for _, collector := range []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		err := wrapped.Register(collector)
		if err != nil {
			return nil, err
		}
	}

	return &handler{base: base, state: s, applications: applications}, nil
}

// ServeHTTP implements http.Handler.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), collectTimeout)
	defer cancel()

	collector := &osCollector{state: h.state}

	if h.applications != nil {
		apps, err := h.applications(ctx)

		switch {
		case err == nil:
			collector.applications = apps
		case errors.Is(ctx.Err(), context.Canceled):
			// The client went away, there is no one to send the metrics to.
			return
		default:
			slog.WarnContext(ctx, "Failed to get installed applications for metrics: "+err.Error())
		}
	}

	// The IncusOS collector already uses prefixed names.
	scrape := prometheus.NewRegistry()

	err := scrape.Register(collector)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	promhttp.HandlerFor(prometheus.Gatherers{h.base, scrape}, promhttp.HandlerOpts{
		ErrorHandling:     promhttp.ContinueOnError,
		EnableOpenMetrics: true,
	}).ServeHTTP(w, r)
}

// BoolToFloat returns 1 for true and 0 for false, the usual metric value for a boolean.
func BoolToFloat(b bool) float64 {
	if b {
		return 1
	}

	return 0
}
