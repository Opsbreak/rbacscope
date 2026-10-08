package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Golden tests run from the repository root so that file paths in output
// are stable ("testdata/cluster/...").
func TestMain(m *testing.M) {
	flag.Parse()
	if err := os.Chdir(filepath.Join("..", "..")); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

const fixture = "testdata/cluster"

func runCLI(args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return out.String(), errb.String(), code
}

func TestGolden(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"audit.txt", []string{"audit", "-f", fixture}},
		{"audit.json", []string{"audit", "-f", fixture, "-o", "json"}},
		{"audit.sarif", []string{"audit", "-f", fixture, "-o", "sarif"}},
		{"audit-high.txt", []string{"audit", "-f", fixture, "--min-severity", "high"}},
		{"who-can-list-secrets.txt", []string{"who-can", "list", "secrets", "-f", fixture}},
		{"who-can-create-pods-ci.txt", []string{"who-can", "create", "pods", "-n", "ci", "-f", fixture}},
		{"who-can-create-pods-exec.txt", []string{"who-can", "create", "pods/exec", "-f", fixture}},
		{"who-can-get-nodes-proxy.json", []string{"who-can", "get", "nodes/proxy", "-f", fixture, "-o", "json"}},
		{"who-can-bind-clusterroles-ci.txt", []string{"who-can", "bind", "clusterroles", "--name", "edit", "-n", "ci", "-f", fixture}},
		{"who-can-get-metrics.txt", []string{"who-can", "get", "/metrics", "-f", fixture}},
		{"can-gitlab-runner.txt", []string{"can", "sa:ci/gitlab-runner", "-f", fixture}},
		{"can-alice.json", []string{"can", "alice", "-f", fixture, "-o", "json"}},
		{"can-prometheus-list-secrets.txt", []string{"can", "sa:monitoring/prometheus", "list", "secrets", "-f", fixture}},
		{"can-bob-get-secret.txt", []string{"can", "bob", "get", "secrets", "-n", "payments", "--name", "payments-db", "-f", fixture}},
		{"can-dev-team-member.txt", []string{"can", "user:dana", "--group", "dev-team", "-f", fixture}},
		{"paths.txt", []string{"paths", "-f", fixture}},
		{"paths.json", []string{"paths", "-f", fixture, "-o", "json"}},
		{"paths.dot", []string{"paths", "-f", fixture, "-o", "dot"}},
		{"paths.mmd", []string{"paths", "-f", fixture, "-o", "mermaid"}},
		{"paths-from-alice.txt", []string{"paths", "--from", "alice", "--to", "sa:dev/default", "-f", fixture}},
		{"paths-from-dana-in-dev-team.txt", []string{"paths", "--from", "dana", "--group", "dev-team", "-f", fixture}},
		{"rules.txt", []string{"rules"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, code := runCLI(tt.args...)
			if code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, stderr)
			}
			golden := filepath.Join("testdata", "golden", tt.name)
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("missing golden file (run go test ./cmd/rbacscope -update): %v", err)
			}
			if got := out; got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Fatalf("output differs from %s; run with -update and review the diff.\n--- got ---\n%s", golden, got)
			}
		})
	}
}

func TestSARIFIsValidJSON(t *testing.T) {
	out, _, code := runCLI("audit", "-f", fixture, "-o", "sarif")
	if code != 0 {
		t.Fatal(code)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != 17 {
		t.Fatalf("bad sarif header: %+v", doc)
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Fatal("expected results")
	}
	for _, r := range doc.Runs[0].Results {
		loc := r.Locations[0].PhysicalLocation
		if !strings.HasPrefix(loc.ArtifactLocation.URI, "testdata/cluster/") || loc.Region.StartLine < 1 {
			t.Fatalf("bad location for %s: %+v", r.RuleID, loc)
		}
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{"fail-on critical trips", []string{"audit", "-f", fixture, "--fail-on", "critical"}, exitFindings},
		{"fail-on with nothing at threshold", []string{"audit", "-f", "testdata/cluster/00-namespaces.yaml", "--fail-on", "info"}, exitOK},
		{"no command", []string{}, exitUsage},
		{"unknown command", []string{"frobnicate"}, exitUsage},
		{"missing input", []string{"audit"}, exitUsage},
		{"bad severity", []string{"audit", "-f", fixture, "--fail-on", "severe"}, exitUsage},
		{"bad output format", []string{"paths", "-f", fixture, "-o", "xml"}, exitUsage},
		{"who-can arity", []string{"who-can", "get", "-f", fixture}, exitUsage},
		{"bad subject", []string{"can", "sa:nonamespace", "-f", fixture}, exitUsage},
		{"missing file", []string{"audit", "-f", "testdata/does-not-exist"}, exitError},
		{"version", []string{"version"}, exitOK},
		{"help", []string{"help"}, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, stderr, code := runCLI(tt.args...)
			if code != tt.code {
				t.Fatalf("exit code %d, want %d (stderr: %s)", code, tt.code, stderr)
			}
		})
	}
}

func TestInterspersedFlags(t *testing.T) {
	a, _, c1 := runCLI("who-can", "-f", fixture, "get", "-n", "ci", "secrets")
	b, _, c2 := runCLI("who-can", "get", "secrets", "-n", "ci", "-f", fixture)
	if c1 != 0 || c2 != 0 || a != b || !strings.Contains(a, "sa:ci/gitlab-runner") {
		t.Fatalf("flag placement changed the result:\n%s\n---\n%s", a, b)
	}
}
