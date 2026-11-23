package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/lxc/incus-os/incus-osd/internal/state"
)

func TestOSCollector(t *testing.T) {
	t.Parallel()

	s := &state.State{}
	s.OS.Name = "IncusOS"
	s.OS.RunningRelease = "202611240000"
	s.OS.NextRelease = "202611250000"
	s.System.Update.State.NeedsReboot = true
	s.System.Update.State.LastCheck = time.Unix(1795000000, 0)
	s.UsingSWTPM = true

	apps := []Application{{Name: "incus", Version: "202611240000"}}

	expected := `
# HELP incusos_application_info Information about an installed application.
# TYPE incusos_application_info gauge
incusos_application_info{name="incus",version="202611240000"} 1
# HELP incusos_info Information about the running IncusOS release.
# TYPE incusos_info gauge
incusos_info{name="IncusOS",version="202611240000"} 1
# HELP incusos_security_secure_boot_enabled Whether Secure Boot is enabled (1) or not (0).
# TYPE incusos_security_secure_boot_enabled gauge
incusos_security_secure_boot_enabled 1
# HELP incusos_security_swtpm_in_use Whether IncusOS uses its own software TPM because no TPM is available (1) or not (0).
# TYPE incusos_security_swtpm_in_use gauge
incusos_security_swtpm_in_use 1
# HELP incusos_update_last_check_timestamp_seconds Time of the last update check, in seconds since the Unix epoch.
# TYPE incusos_update_last_check_timestamp_seconds gauge
incusos_update_last_check_timestamp_seconds 1.795e+09
# HELP incusos_update_needs_reboot Whether an update has been applied that requires a reboot (1) or not (0).
# TYPE incusos_update_needs_reboot gauge
incusos_update_needs_reboot 1
# HELP incusos_update_next_release_info Information about the IncusOS release that will be used on next boot, if it differs from the running one.
# TYPE incusos_update_next_release_info gauge
incusos_update_next_release_info{version="202611250000"} 1
`

	err := testutil.CollectAndCompare(&osCollector{state: s, applications: apps}, strings.NewReader(expected))
	require.NoError(t, err)
}

func TestOSCollectorOptionalMetrics(t *testing.T) {
	t.Parallel()

	s := &state.State{}

	// No next release, no last check and no applications: only the always-present metrics.
	count := testutil.CollectAndCount(&osCollector{state: s})
	require.Equal(t, 4, count)
}

func TestOSCollectorNextReleaseRunning(t *testing.T) {
	t.Parallel()

	// After booting into the next release, it's still recorded as the next one.
	s := &state.State{}
	s.OS.RunningRelease = "202611240158"
	s.OS.NextRelease = "202611240158"

	count := testutil.CollectAndCount(&osCollector{state: s}, Prefix+"update_next_release_info")
	require.Equal(t, 0, count)
}

type testContextKey struct{}

func scrape(ctx context.Context, t *testing.T, h http.Handler) string {
	t.Helper()

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/1.0/metrics", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	return rec.Body.String()
}

func TestHandler(t *testing.T) {
	t.Parallel()

	calls := 0

	apps := func(ctx context.Context) ([]Application, error) {
		calls++

		// The applications are listed within the request's context, with a deadline.
		require.Equal(t, "scrape", ctx.Value(testContextKey{}))

		_, ok := ctx.Deadline()
		require.True(t, ok)

		return []Application{{Name: "incus", Version: "1"}}, nil
	}

	h, err := NewHandler(&state.State{}, apps)
	require.NoError(t, err)

	body := scrape(context.WithValue(t.Context(), testContextKey{}, "scrape"), t, h)
	require.Equal(t, 1, calls)
	require.Contains(t, body, `incusos_application_info{name="incus",version="1"} 1`)
	require.Contains(t, body, "incusos_go_goroutines ")

	// Every metric uses the prefix, including the Go runtime and process ones.
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		require.True(t, strings.HasPrefix(line, Prefix), line)
	}
}

func TestHandlerFailingApplications(t *testing.T) {
	t.Parallel()

	failingApps := func(_ context.Context) ([]Application, error) {
		return nil, errors.New("boom")
	}

	h, err := NewHandler(&state.State{}, failingApps)
	require.NoError(t, err)

	// The other metrics are still served.
	body := scrape(t.Context(), t, h)
	require.Contains(t, body, "incusos_info{")
	require.NotContains(t, body, "incusos_application_info")
}

func TestHandlerCanceled(t *testing.T) {
	t.Parallel()

	apps := func(ctx context.Context) ([]Application, error) {
		return nil, ctx.Err()
	}

	h, err := NewHandler(&state.State{}, apps)
	require.NoError(t, err)

	// A scrape whose client went away is dropped without a response.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/1.0/metrics", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	require.Empty(t, rec.Body.String())
}
