// Package audit evaluates RBAC risk rules (RS001...) over an rbac.Engine.
package audit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity of a finding.
type Severity int

// Severities in ascending order.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var sevNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return sevNames[s]
}

// MarshalJSON renders the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity parses a severity name (case-insensitive).
func ParseSeverity(s string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(s, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want one of %s)", s, strings.Join(sevNames, ", "))
}

// Lower returns the next lower severity (never below Info).
func (s Severity) Lower() Severity {
	if s <= Info {
		return Info
	}
	return s - 1
}

// SARIFLevel maps the severity to a SARIF result level.
func (s Severity) SARIFLevel() string {
	switch s {
	case Critical, High:
		return "error"
	case Medium:
		return "warning"
	}
	return "note"
}

// SecurityScore maps the severity to GitHub code scanning's numeric
// "security-severity" property (critical >= 9.0, high >= 7.0, medium >= 4.0).
func (s Severity) SecurityScore() string {
	switch s {
	case Critical:
		return "9.5"
	case High:
		return "8.0"
	case Medium:
		return "5.5"
	case Low:
		return "3.0"
	}
	return "1.0"
}
