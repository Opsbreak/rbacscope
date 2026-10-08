package report

import (
	"io"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/audit"
	"github.com/Opsbreak/rbacscope/internal/model"
)

// SARIF 2.1.0 object model (the subset rbacscope emits).
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name"`
	ShortDescription     sarifText       `json:"shortDescription"`
	FullDescription      sarifText       `json:"fullDescription"`
	Help                 sarifText       `json:"help"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig `json:"defaultConfiguration"`
	Properties           sarifRuleProps  `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
	Precision        string   `json:"precision"`
}

type sarifResult struct {
	RuleID              string                 `json:"ruleId"`
	RuleIndex           int                    `json:"ruleIndex"`
	Level               string                 `json:"level"`
	Message             sarifText              `json:"message"`
	Locations           []sarifLocation        `json:"locations"`
	RelatedLocations    []sarifLocation        `json:"relatedLocations,omitempty"`
	PartialFingerprints map[string]string      `json:"partialFingerprints"`
	Properties          map[string]interface{} `json:"properties"`
}

type sarifLocation struct {
	ID               *int                  `json:"id,omitempty"`
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifText            `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

const informationURI = "https://github.com/Opsbreak/rbacscope"

func location(src model.Source, msg string) sarifLocation {
	uri := strings.TrimPrefix(src.File, "./")
	if uri == "" {
		uri = "unknown"
	}
	l := sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: uri}}}
	if src.Line > 0 {
		l.PhysicalLocation.Region = &sarifRegion{StartLine: src.Line}
	}
	if msg != "" {
		l.Message = &sarifText{Text: msg}
	}
	return l
}

// SARIF writes findings as a SARIF 2.1.0 log.
func SARIF(w io.Writer, version string, findings []audit.Finding) error {
	driver := sarifDriver{Name: "rbacscope", Version: version, InformationURI: informationURI}
	index := map[string]int{}
	for i, r := range audit.Rules {
		index[r.ID] = i
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   r.ID,
			Name:                 r.Name,
			ShortDescription:     sarifText{Text: r.Title},
			FullDescription:      sarifText{Text: r.Description},
			Help:                 sarifText{Text: r.Description + "\n\nRemediation: " + r.Remediation},
			HelpURI:              informationURI + "#audit-rules",
			DefaultConfiguration: sarifRuleConfig{Level: r.Severity.SARIFLevel()},
			Properties: sarifRuleProps{
				Tags:             []string{"security", "kubernetes", "rbac"},
				SecuritySeverity: r.Severity.SecurityScore(),
				Precision:        "high",
			},
		})
	}
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		res := sarifResult{
			RuleID:              f.RuleID,
			RuleIndex:           index[f.RuleID],
			Level:               f.Severity.SARIFLevel(),
			Message:             sarifText{Text: f.Message},
			Locations:           []sarifLocation{location(f.Location, "")},
			PartialFingerprints: map[string]string{"rbacscope/v1": f.Fingerprint},
			Properties: map[string]interface{}{
				"severity":          f.Severity.String(),
				"security-severity": f.Severity.SecurityScore(),
			},
		}
		if len(f.Subjects) > 0 {
			res.Properties["subjects"] = f.Subjects
		}
		for i, r := range f.Related {
			l := location(r.Source, r.Message)
			id := i + 1
			l.ID = &id
			res.RelatedLocations = append(res.RelatedLocations, l)
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	return JSON(w, log)
}
