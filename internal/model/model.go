// Package model defines the versioned, engine-independent public configuration.
package model

import (
	"encoding/json"
	"time"
)

const SchemaVersion = 1

type Config struct {
	SchemaVersion int           `json:"schema_version"`
	Revision      uint64        `json:"revision"`
	Role          string        `json:"role"`
	Sources       []Source      `json:"sources"`
	Targets       []Target      `json:"targets"`
	Policy        Policy        `json:"policy"`
	Probes        ProbeSettings `json:"probes"`
	Network       Network       `json:"network"`
}
type Source struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Enabled  bool            `json:"enabled"`
	Auto     bool            `json:"auto"`
	Settings json.RawMessage `json:"settings"`
}
type Target struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Required    bool   `json:"required"`
	StatusCodes []int  `json:"status_codes"`
	MaxBytes    int64  `json:"max_bytes"`
}
type Policy struct {
	Mode                  string  `json:"mode"`
	Pinned                string  `json:"pinned,omitempty"`
	Fallback              string  `json:"fallback"`
	ImprovementPercent    float64 `json:"improvement_percent"`
	Confirmations         int     `json:"confirmations"`
	FailureConfirmations  int     `json:"failure_confirmations"`
	RecoveryConfirmations int     `json:"recovery_confirmations"`
	MinDwellSeconds       int     `json:"min_dwell_seconds"`
	CooldownSeconds       int     `json:"cooldown_seconds"`
	StaleAfterSeconds     int     `json:"stale_after_seconds"`
	BreakExisting         bool    `json:"break_existing"`
}
type ProbeSettings struct {
	ActiveIntervalSeconds int `json:"active_interval_seconds"`
	OtherIntervalSeconds  int `json:"other_interval_seconds"`
	SpeedIntervalSeconds  int `json:"speed_interval_seconds"`
	TimeoutSeconds        int `json:"timeout_seconds"`
	Concurrency           int `json:"concurrency"`
	HistoryLimit          int `json:"history_limit"`
}
type Network struct {
	Enabled       bool     `json:"enabled"`
	LANInterfaces []string `json:"lan_interfaces"`
	WANInterface  string   `json:"wan_interface,omitempty"`
	LocalPrefixes []string `json:"local_prefixes"`
	IPv6          string   `json:"ipv6"`
	DNS           string   `json:"dns"`
	DNSResolver   string   `json:"dns_resolver,omitempty"`
}
type ResourceResult struct {
	TargetID   string   `json:"target_id"`
	Required   bool     `json:"required"`
	Success    bool     `json:"success"`
	StatusCode int      `json:"status_code,omitempty"`
	LatencyMS  float64  `json:"latency_ms"`
	Bytes      int64    `json:"bytes"`
	SpeedBPS   *float64 `json:"speed_bps,omitempty"`
	ErrorCode  string   `json:"error_code,omitempty"`
}
type Measurement struct {
	SourceID   string           `json:"source_id"`
	At         time.Time        `json:"at"`
	Path       string           `json:"path"`
	Resources  []ResourceResult `json:"resources"`
	PacketLoss *float64         `json:"packet_loss,omitempty"`
}
type SourceHealth struct {
	SourceID             string           `json:"source_id"`
	State                string           `json:"state"`
	LastAt               time.Time        `json:"last_at"`
	SuccessRate          float64          `json:"success_rate"`
	LatencyMS            float64          `json:"latency_ms"`
	SpeedBPS             *float64         `json:"speed_bps,omitempty"`
	PacketLoss           *float64         `json:"packet_loss,omitempty"`
	ConsecutiveFailures  int              `json:"consecutive_failures"`
	ConsecutiveSuccesses int              `json:"consecutive_successes"`
	Resources            []ResourceResult `json:"resources,omitempty"`
}
type Decision struct {
	At       time.Time `json:"at"`
	Previous string    `json:"previous,omitempty"`
	Selected string    `json:"selected,omitempty"`
	Changed  bool      `json:"changed"`
	State    string    `json:"state"`
	Reason   string    `json:"reason"`
}
