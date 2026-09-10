package model

// RoutingConfig is absent in legacy schema-1 configurations. Its presence never
// changes a confirmed network until a new network transaction is confirmed.
type RoutingConfig struct {
	Mode          string           `json:"mode"`
	FailurePolicy string           `json:"failure_policy"`
	Registry      RoutingRegistry  `json:"registry"`
	Detection     RoutingDetection `json:"detection"`
	Exceptions    []RoutingRule    `json:"exceptions"`
}

type RoutingRegistry struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
}

type RoutingDetection struct {
	Enabled          bool     `json:"enabled"`
	ControlTargetIDs []string `json:"control_target_ids"`
}

// Exactly one of Domain and CIDR must be set. Domain rules are exact unless
// IncludeSubdomains is explicitly enabled; resolved CDN addresses are never rules.
type RoutingRule struct {
	Action            string `json:"action"`
	Domain            string `json:"domain,omitempty"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty"`
	CIDR              string `json:"cidr,omitempty"`
}

func SelectiveRouting(c Config) bool { return c.Routing != nil && c.Routing.Mode == "selective" }
