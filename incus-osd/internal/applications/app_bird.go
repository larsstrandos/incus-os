package applications

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/lxc/incus/v7/shared/subprocess"

	"github.com/lxc/incus-os/incus-osd/api"
	"github.com/lxc/incus-os/incus-osd/internal/nftables"
	"github.com/lxc/incus-os/incus-osd/internal/rest/response"
	"github.com/lxc/incus-os/incus-osd/internal/state"
	"github.com/lxc/incus-os/incus-osd/internal/systemd"
)

const (
	birdConfigDir  = "/var/lib/bird/"
	birdConfigPath = birdConfigDir + "bird.conf"
	birdSocketPath = "/run/bird/bird.ctl"
)

type bird struct {
	common
}

// configured reports whether there is anything for BIRD to run: a raw configuration or EVPN.
func (b *bird) configured() bool {
	return b.state.Applications.Bird.Config.Config != "" || b.state.Applications.Bird.Config.EVPN != nil
}

// Debug runs a read-only birdc command.
func (*bird) Debug(ctx context.Context, data any) response.Response {
	req, ok := data.(*api.ApplicationAction)
	if !ok {
		return response.BadRequest(errors.New("invalid request data type"))
	}

	if req.Action != "birdc" {
		return response.NotImplemented(nil)
	}

	args := strings.Fields(req.Config["command"])
	if len(args) == 0 {
		args = []string{"show", "protocols"}
	}

	// Restricted mode only allows "show" style commands.
	output, err := subprocess.RunCommandContext(ctx, "birdc", append([]string{"-r", "-s", birdSocketPath}, args...)...)
	if err != nil {
		return response.InternalError(err)
	}

	return response.SyncResponse(true, output)
}

// DebugStruct returns the struct to fill with debug request data.
func (*bird) DebugStruct() any {
	return &api.ApplicationAction{}
}

// FactoryReset performs a full factory reset of the application.
func (b *bird) FactoryReset(ctx context.Context) error {
	err := b.Stop(ctx)
	if err != nil {
		return err
	}

	err = b.WipeLocalData(ctx)
	if err != nil {
		return err
	}

	b.state.Applications.Bird.Config.Config = ""
	b.state.Applications.Bird.Config.EVPN = nil

	return nil
}

func (b *bird) Get(_ context.Context) (any, error) {
	return b.state.Applications.Bird, nil
}

// GetBackup returns a tar archive backup of the application's configuration.
func (*bird) GetBackup(archive io.Writer, _ bool) error {
	return createTarArchive(birdConfigDir, nil, archive)
}

// IsInstalled reports whether the application has been installed.
func (b *bird) IsInstalled() bool {
	return isInstalled(b.Name(), b.appState.Version)
}

func (*bird) IsRunning(ctx context.Context) bool {
	return systemd.IsActive(ctx, "bird.service")
}

func (*bird) Name() string {
	return "bird"
}

// Restart restarts the daemon.
func (b *bird) Restart(ctx context.Context) error {
	err := b.writeConfig()
	if err != nil {
		return err
	}

	if !b.configured() {
		return nil
	}

	return systemd.RestartUnit(ctx, "bird.service")
}

// RestoreBackup restores a tar archive backup of the application's configuration.
func (b *bird) RestoreBackup(archive io.Reader) error {
	err := extractTarArchive(birdConfigDir, []string{"bird.service"}, archive)
	if err != nil {
		return err
	}

	contents, err := os.ReadFile(birdConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	b.state.Applications.Bird.Config.Config = birdRawConfig(string(contents))

	return nil
}

// SetFriendlyVersion records the friendly version.
func (b *bird) SetFriendlyVersion(ctx context.Context) error {
	_, stderr, err := subprocess.RunCommandSplit(ctx, nil, nil, "bird", "--version")
	if err != nil {
		return err
	}

	versionGroup := regexp.MustCompile(`BIRD version (\S+)`).FindStringSubmatch(stderr)
	if len(versionGroup) != 2 {
		return errors.New("unable to determine BIRD version")
	}

	b.appState.FriendlyVersion = versionGroup[1] + " [" + b.appState.Version + "]"

	return nil
}

// Start writes the configuration, opens the firewall and starts the daemon.
func (b *bird) Start(ctx context.Context) error {
	err := b.writeConfig()
	if err != nil {
		return err
	}

	// Re-apply input filters so the BGP and BFD rules are present.
	if b.state.System.Network.Config != nil {
		err = nftables.ApplyInputFilters(ctx, b.state.System.Network.Config)
		if err != nil {
			return err
		}
	}

	if !b.configured() {
		return nil
	}

	return systemd.StartUnit(ctx, "bird.service")
}

// Stop stops the daemon.
func (*bird) Stop(ctx context.Context) error {
	return systemd.StopUnit(ctx, "bird.service")
}

func (*bird) Struct() any {
	return &api.ApplicationBird{}
}

// Update applies an application update, restarting BIRD only when its binary changed.
func (b *bird) Update(ctx context.Context) error {
	err := systemd.ReloadDaemon(ctx)
	if err != nil {
		return err
	}

	// Only restart when the BIRD binary changed, otherwise keep the sessions up.
	if !b.IsRunning(ctx) || birdBinaryChanged(ctx) {
		return b.Restart(ctx)
	}

	err = b.writeConfig()
	if err != nil {
		return err
	}

	_, err = subprocess.RunCommandContext(ctx, "birdc", "-s", birdSocketPath, "configure")

	return err
}

// birdBinaryChanged reports whether the running daemon uses a different binary than /usr/sbin/bird.
func birdBinaryChanged(ctx context.Context) bool {
	pid, err := subprocess.RunCommandContext(ctx, "systemctl", "show", "bird.service", "-p", "MainPID", "--value")
	if err != nil {
		return true
	}

	pid = strings.TrimSpace(pid)
	if pid == "" || pid == "0" {
		return true
	}

	running, err := fileSHA256("/proc/" + pid + "/exe")
	if err != nil {
		return true
	}

	installed, err := fileSHA256("/usr/sbin/bird")
	if err != nil {
		return true
	}

	return running != installed
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer func() { _ = f.Close() }()

	h := sha256.New()

	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// UpdateConfig validates and applies a new bird.conf and EVPN settings.
func (b *bird) UpdateConfig(ctx context.Context, req any) error {
	newState, ok := req.(*api.ApplicationBird)
	if !ok {
		return fmt.Errorf("request type \"%T\" isn't expected ApplicationBird", req)
	}

	newConfig, err := birdFullConfig(newState.Config.Config, b.state.System.Network.Config, newState.Config.EVPN)
	if err != nil {
		return err
	}

	if newConfig != "" {
		err := validateBirdConfig(ctx, newConfig)
		if err != nil {
			return err
		}
	}

	b.state.Applications.Bird.Config = newState.Config

	return b.apply(ctx, newConfig)
}

// apply writes a full configuration and starts, reconfigures or stops BIRD to match.
func (b *bird) apply(ctx context.Context, cfg string) error {
	oldCfg, err := os.ReadFile(birdConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	err = writeBirdConfig(cfg)
	if err != nil {
		return err
	}

	if cfg == "" {
		return b.Stop(ctx)
	}

	if !b.IsRunning(ctx) {
		return systemd.StartUnit(ctx, "bird.service")
	}

	_, err = subprocess.RunCommandContext(ctx, "birdc", "-s", birdSocketPath, "configure")
	if err != nil {
		return fmt.Errorf("failed to reconfigure BIRD: %w", err)
	}

	// BIRD keeps the old route target on the IMET route of an EVPN protocol whose export target changed, so
	// the other VTEPs stop flooding to this one. Restarting the changed EVPN protocols re-announces it.
	for _, protocol := range changedBirdEVPNProtocols(string(oldCfg), cfg) {
		_, err = subprocess.RunCommandContext(ctx, "birdc", "-s", birdSocketPath, "restart", protocol)
		if err != nil {
			return fmt.Errorf("failed to restart BIRD protocol %s: %w", protocol, err)
		}
	}

	return nil
}

// ValidateBirdEVPN checks that the EVPN settings of the BIRD application still work with a new network
// configuration.
func ValidateBirdEVPN(s *state.State, netCfg *api.SystemNetworkConfig) error {
	_, err := birdEVPNConfig(netCfg, s.Applications.Bird.Config.EVPN)
	if err != nil {
		return fmt.Errorf("the bird application's evpn settings don't fit the new network configuration: %w", err)
	}

	return nil
}

// RefreshBirdEVPN regenerates the EVPN part of bird.conf after a network configuration change and reconfigures
// BIRD, when the BIRD application is installed and has EVPN settings.
func RefreshBirdEVPN(ctx context.Context, s *state.State) error {
	if s.Applications.Bird.Config.EVPN == nil {
		return nil
	}

	b := &bird{common: common{state: s, appConfig: &s.Applications.Bird.Config.ApplicationConfig, appState: &s.Applications.Bird.State}}
	if !b.IsInstalled() {
		return nil
	}

	cfg, err := birdFullConfig(s.Applications.Bird.Config.Config, s.System.Network.Config, s.Applications.Bird.Config.EVPN)
	if err != nil {
		return err
	}

	err = validateBirdConfig(ctx, cfg)
	if err != nil {
		return err
	}

	return b.apply(ctx, cfg)
}

// WipeLocalData removes the on-disk configuration.
func (*bird) WipeLocalData(_ context.Context) error {
	err := os.RemoveAll(birdConfigDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// writeConfig writes the configuration from the state to disk, or removes it.
func (b *bird) writeConfig() error {
	cfg, err := birdFullConfig(b.state.Applications.Bird.Config.Config, b.state.System.Network.Config, b.state.Applications.Bird.Config.EVPN)
	if err != nil {
		return err
	}

	return writeBirdConfig(cfg)
}

// writeBirdConfig writes a full configuration to disk, or removes it.
func writeBirdConfig(cfg string) error {
	if cfg == "" {
		err := os.Remove(birdConfigPath)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		return nil
	}

	err := os.MkdirAll(birdConfigDir, 0o700)
	if err != nil {
		return err
	}

	err = os.WriteFile(birdConfigPath+".new", []byte(cfg), 0o600)
	if err != nil {
		return err
	}

	return os.Rename(birdConfigPath+".new", birdConfigPath)
}

// birdRawConfig strips the parts IncusOS generated from a bird.conf read back from disk.
func birdRawConfig(contents string) string {
	raw, _, _ := strings.Cut(contents, birdEVPNHeader)
	if strings.HasPrefix(raw, birdMinimalHeader) {
		return ""
	}

	return strings.TrimRight(raw, "\n") + "\n"
}

func validateBirdConfig(ctx context.Context, cfg string) error {
	f, err := os.CreateTemp("", "bird-*.conf")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(f.Name()) }()

	_, err = f.WriteString(cfg)
	if err != nil {
		_ = f.Close()

		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	_, stderr, err := subprocess.RunCommandSplit(ctx, nil, nil, "bird", "-p", "-c", f.Name())
	if err != nil {
		return fmt.Errorf("invalid BIRD configuration: %s", strings.TrimSpace(stderr))
	}

	return nil
}
