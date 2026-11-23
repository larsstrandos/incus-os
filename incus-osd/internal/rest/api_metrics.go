package rest

import (
	"context"
	"net/http"

	"github.com/lxc/incus-os/incus-osd/internal/applications"
	"github.com/lxc/incus-os/incus-osd/internal/metrics"
	"github.com/lxc/incus-os/incus-osd/internal/rest/response"
)

// swagger:operation GET /1.0/metrics metrics metrics_get
//
//	Get metrics
//
//	Returns IncusOS metrics in the Prometheus/OpenMetrics text format.
//	All metric names are prefixed with "incusos_".
//
//	---
//	produces:
//	  - text/plain
//	  - application/openmetrics-text
//	responses:
//	  "200":
//	    description: Metrics
//	    schema:
//	      type: string
//	      example: |-
//	        # HELP incusos_update_needs_reboot Whether an update has been applied that requires a reboot (1) or not (0).
//	        # TYPE incusos_update_needs_reboot gauge
//	        incusos_update_needs_reboot 0
//	  "500":
//	    $ref: "#/responses/InternalServerError"
func (s *Server) apiMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = response.NotImplemented(nil).Render(w)

		return
	}

	s.metrics.ServeHTTP(w, r)
}

// installedApplications returns the installed applications for the metrics collector.
func (s *Server) installedApplications(ctx context.Context) ([]metrics.Application, error) {
	apps, err := applications.GetInstalled(ctx, s.state)
	if err != nil {
		return nil, err
	}

	out := make([]metrics.Application, 0, len(apps))
	for _, app := range apps {
		out = append(out, metrics.Application{Name: app.Name(), Version: app.Version()})
	}

	return out, nil
}
