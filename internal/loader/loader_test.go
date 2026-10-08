package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opsbreak/rbacscope/internal/model"
)

func TestLoadBytes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		check func(t *testing.T, input string)
	}{
		{"multi-document yaml with line numbers", `# comment
apiVersion: v1
kind: ServiceAccount
metadata:
  name: a
  namespace: ns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: r
rules:
- verbs: [get]
  apiGroups: [""]
  resources: [pods]
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.ServiceAccounts) != 1 || c.ServiceAccounts[0].Source.Line != 2 {
				t.Fatalf("sa: %+v", c.ServiceAccounts)
			}
			if len(c.ClusterRoles) != 1 || c.ClusterRoles[0].Source.Line != 8 || len(c.ClusterRoles[0].Rules) != 1 {
				t.Fatalf("cr: %+v", c.ClusterRoles)
			}
		}},
		{"kind List items keep their own lines", `apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Namespace
  metadata: {name: one}
- apiVersion: v1
  kind: Namespace
  metadata: {name: two}
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.Namespaces) != 2 || c.Namespaces[1].Source.Line != 7 {
				t.Fatalf("ns: %+v", c.Namespaces)
			}
		}},
		{"typed lists such as RoleBindingList", `{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBindingList","items":[
{"kind":"RoleBinding","metadata":{"name":"b","namespace":"x"},"roleRef":{"kind":"Role","name":"r"},"subjects":[{"kind":"ServiceAccount","name":"s"}]}]}`,
			func(t *testing.T, in string) {
				c := mustLoad(t, in)
				if len(c.RoleBindings) != 1 || c.RoleBindings[0].Subjects[0].Namespace != "x" {
					t.Fatalf("SA namespace not defaulted: %+v", c.RoleBindings)
				}
			}},
		{"workloads become pod templates", `apiVersion: batch/v1
kind: CronJob
metadata: {name: cj, namespace: n}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: worker
          automountServiceAccountToken: false
          containers: [{name: c, securityContext: {privileged: true}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: n}
spec:
  template:
    spec:
      serviceAccount: legacy
      volumes: [{name: v, hostPath: {path: /}}]
---
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: n}
spec: {nodeName: node-1}
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.Pods) != 3 {
				t.Fatalf("pods: %d", len(c.Pods))
			}
			cj, d, p := c.Pods[0], c.Pods[1], c.Pods[2]
			if cj.OwnerKind != "CronJob" || cj.ServiceAccountName != "worker" || cj.AutomountServiceAccountToken == nil || *cj.AutomountServiceAccountToken || !cj.Privileged {
				t.Fatalf("cronjob: %+v", cj)
			}
			if d.ServiceAccountName != "legacy" || !d.HostPath {
				t.Fatalf("deployment: %+v", d)
			}
			if p.ServiceAccountName != "default" || p.NodeName != "node-1" || p.OwnerKind != "" {
				t.Fatalf("pod: %+v", p)
			}
		}},
		{"secret data is never decoded and unknown kinds are counted", `apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: tok
  namespace: n
  annotations: {kubernetes.io/service-account.name: sa}
data:
  token: c2VjcmV0
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cm}
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.Secrets) != 1 || c.Secrets[0].Type != "kubernetes.io/service-account-token" {
				t.Fatalf("secrets: %+v", c.Secrets)
			}
			if c.Skipped["ConfigMap"] != 1 {
				t.Fatalf("skipped: %v", c.Skipped)
			}
		}},
		{"duplicates warn and last wins", `kind: ClusterRole
metadata: {name: r}
rules: [{verbs: [get], apiGroups: [""], resources: [pods]}]
---
kind: ClusterRole
metadata: {name: r}
rules: [{verbs: [list], apiGroups: [""], resources: [pods]}]
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.ClusterRoles) != 1 || c.ClusterRoles[0].Rules[0].Verbs[0] != "list" || len(c.Warnings) != 1 {
				t.Fatalf("got %+v warnings=%v", c.ClusterRoles, c.Warnings)
			}
		}},
		{"ClusterRoleBinding SA subject without namespace warns", `kind: ClusterRoleBinding
metadata: {name: b}
roleRef: {kind: ClusterRole, name: r}
subjects: [{kind: ServiceAccount, name: s}]
`, func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "without namespace") {
				t.Fatalf("warnings: %v", c.Warnings)
			}
		}},
		{"BOM and empty documents", "\xef\xbb\xbf---\n---\nkind: Namespace\nmetadata: {name: x}\n", func(t *testing.T, in string) {
			c := mustLoad(t, in)
			if len(c.Namespaces) != 1 {
				t.Fatalf("ns: %+v", c.Namespaces)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.check(t, tt.input) })
	}
}

func TestLoadBytesError(t *testing.T) {
	if _, err := LoadBytes("bad.yaml", []byte("kind: Role\nrules: [\n")); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := LoadBytes("bad.yaml", []byte("kind: Role\nmetadata: {name: x}\nrules: notalist\n")); err == nil || !strings.Contains(err.Error(), "bad.yaml:1") {
		t.Fatalf("expected decode error with location, got %v", err)
	}
}

func TestLoadPathsDirectory(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("b.yaml", "kind: Namespace\nmetadata: {name: b}\n")
	write("sub/a.json", `{"kind":"Namespace","metadata":{"name":"a"}}`)
	write("notes.txt", "kind: Namespace\nmetadata: {name: ignored}\n")
	write(".hidden/c.yaml", "kind: Namespace\nmetadata: {name: hidden}\n")
	c, err := LoadPaths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, n := range c.Namespaces {
		names = append(names, n.Meta.Name)
	}
	if strings.Join(names, ",") != "b,a" {
		t.Fatalf("got %v", names)
	}
	if !strings.HasSuffix(c.Namespaces[1].Source.File, "sub/a.json") {
		t.Fatalf("source path not slash-normalised: %s", c.Namespaces[1].Source.File)
	}
}

func mustLoad(t *testing.T, in string) *model.Cluster {
	t.Helper()
	c, err := LoadBytes("test.yaml", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
