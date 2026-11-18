package api

// ApplicationBirdConfig represents additional configuration for the BIRD application.
type ApplicationBirdConfig struct {
	ApplicationConfig

	// Raw bird.conf contents, validated with "bird -p" before being applied.
	Config string `json:"config" yaml:"config"`
}

// ApplicationBird represents the state and configuration of the BIRD application.
type ApplicationBird struct {
	State ApplicationState `json:"state" yaml:"state"`

	Config ApplicationBirdConfig `json:"config" yaml:"config"`
}
