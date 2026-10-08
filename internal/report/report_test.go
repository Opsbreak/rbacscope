package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Opsbreak/rbacscope/internal/audit"
	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/paths"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

func TestTable(t *testing.T) {
	tb := &Table{Header: []string{"A", "BB", "C"}}
	tb.Add("long-value", "x", "")
	tb.Add("y", "zz", "last")
	var b bytes.Buffer
	if err := tb.Write(&b); err != nil {
		t.Fatal(err)
	}
	want := "A           BB  C\nlong-value  x\ny           zz  last\n"
	if b.String() != want {
		t.Fatalf("got\n%q\nwant\n%q", b.String(), want)
	}
}

func TestJoin(t *testing.T) {
	if got := Join([]string{"", "apps"}); got != `"",apps` {
		t.Fatal(got)
	}
	if got := Join(nil); got != "-" {
		t.Fatal(got)
	}
}

func samplePaths() []paths.Path {
	return []paths.Path{{
		Source: rbac.UserID("mallory"), Target: paths.AdminNode,
		Hops: []paths.Edge{
			{From: "user:mallory", To: "sa:ns/x", Technique: paths.TechNodeProxy, Approximate: true},
			{From: "sa:ns/x", To: paths.AdminNode, Technique: paths.TechClusterAdmin},
		},
	}}
}

func TestDOT(t *testing.T) {
	var b bytes.Buffer
	if err := DOT(&b, samplePaths()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"digraph rbacscope {", `"user:mallory" -> "sa:ns/x" [label="kubelet-nodes-proxy", style=dashed];`, `"cluster-admin" [shape=doubleoctagon`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}

func TestMermaid(t *testing.T) {
	var b bytes.Buffer
	if err := Mermaid(&b, samplePaths()); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"flowchart LR", `n0{{"cluster-admin"}}`, "-.->|kubelet-nodes-proxy|", "-->|holds-cluster-admin|"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}

func TestSARIF(t *testing.T) {
	f := audit.Finding{
		RuleID: "RS008", Severity: audit.Critical, Message: "m", Fingerprint: "abc",
		Location: model.Source{File: "./dir/x.yaml", Line: 7},
		Related:  []audit.Related{{Source: model.Source{File: "dir/r.yaml", Line: 2}, Message: "role"}},
	}
	var b bytes.Buffer
	if err := SARIF(&b, "test", []audit.Finding{f}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	res := run["results"].([]interface{})[0].(map[string]interface{})
	if res["level"] != "error" || res["ruleIndex"].(float64) != 7 {
		t.Fatalf("result: %v", res)
	}
	loc := res["locations"].([]interface{})[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})
	if loc["artifactLocation"].(map[string]interface{})["uri"] != "dir/x.yaml" || loc["region"].(map[string]interface{})["startLine"].(float64) != 7 {
		t.Fatalf("location: %v", loc)
	}
}
