package paths

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Opsbreak/rbacscope/internal/loader"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

const base = `
kind: ClusterRole
metadata: {name: cluster-admin}
rules:
- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
---
kind: ClusterRole
metadata: {name: edit}
rules:
- {apiGroups: [""], resources: [pods], verbs: [create]}
---
kind: ServiceAccount
metadata: {name: admin-bot, namespace: prod}
---
kind: ClusterRoleBinding
metadata: {name: admin-bot}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: admin-bot, namespace: prod}]
`

func cr(name, rules string) string {
	return fmt.Sprintf("kind: ClusterRole\nmetadata: {name: %s}\nrules:\n%s", name, rules)
}

func crbTo(role, subject string) string {
	return fmt.Sprintf("kind: ClusterRoleBinding\nmetadata: {name: b-%s}\nroleRef: {kind: ClusterRole, name: %s}\nsubjects: [%s]", role, role, subject)
}

func rbTo(ns, role, subject string) string {
	return fmt.Sprintf("kind: RoleBinding\nmetadata: {name: b-%s, namespace: %s}\nroleRef: {kind: ClusterRole, name: %s}\nsubjects: [%s]", role, ns, role, subject)
}

const mallory = "{kind: User, name: mallory}"

func build(t testing.TB, docs ...string) *Graph {
	t.Helper()
	c, err := loader.LoadBytes("t.yaml", []byte(base+"\n---\n"+strings.Join(docs, "\n---\n")))
	if err != nil {
		t.Fatal(err)
	}
	return Build(rbac.NewEngine(c), Options{})
}

func techniques(hops []Edge) string {
	var out []string
	for _, h := range hops {
		out = append(out, string(h.Technique))
	}
	return strings.Join(out, ",")
}

func TestPaths(t *testing.T) {
	tests := []struct {
		name string
		docs []string
		want string // comma separated techniques; "" = unreachable
	}{
		{"create pods in namespace with admin SA",
			[]string{cr("r", `- {apiGroups: [""], resources: [pods], verbs: [create]}`), rbTo("prod", "r", mallory)},
			"create-pod,holds-cluster-admin"},
		{"create pods in other namespace is not a path",
			[]string{cr("r", `- {apiGroups: [""], resources: [pods], verbs: [create]}`), rbTo("dev", "r", mallory)},
			""},
		{"create deployments",
			[]string{cr("r", `- {apiGroups: [apps], resources: [deployments], verbs: [create]}`), rbTo("prod", "r", mallory)},
			"modify-workload,holds-cluster-admin"},
		{"patch existing deployment",
			[]string{cr("r", `- {apiGroups: [apps], resources: [deployments], verbs: [patch], resourceNames: [web]}`), rbTo("prod", "r", mallory),
				"kind: Deployment\nmetadata: {name: web, namespace: prod}\nspec: {template: {spec: {serviceAccountName: other}}}"},
			"modify-workload,holds-cluster-admin"},
		{"patch of a non-existent deployment name is not a path",
			[]string{cr("r", `- {apiGroups: [apps], resources: [deployments], verbs: [patch], resourceNames: [nope]}`), rbTo("prod", "r", mallory),
				"kind: Deployment\nmetadata: {name: web, namespace: prod}\nspec: {template: {spec: {serviceAccountName: other}}}"},
			""},
		{"token request",
			[]string{cr("r", `- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create]}`), rbTo("prod", "r", mallory)},
			"create-token,holds-cluster-admin"},
		{"token request restricted to other SA",
			[]string{cr("r", `- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create], resourceNames: [someone-else]}`), rbTo("prod", "r", mallory)},
			""},
		{"impersonate groups (system:masters)",
			[]string{cr("r", `- {apiGroups: [""], resources: [users, groups], verbs: [impersonate]}`), crbTo("r", mallory)},
			"impersonate,holds-cluster-admin"},
		{"impersonate groups without users is not a path",
			[]string{cr("r", `- {apiGroups: [""], resources: [groups], verbs: [impersonate]}`), crbTo("r", mallory)},
			""},
		{"impersonate serviceaccount",
			[]string{cr("r", `- {apiGroups: [""], resources: [serviceaccounts], verbs: [impersonate], resourceNames: [admin-bot]}`), rbTo("prod", "r", mallory)},
			"impersonate,holds-cluster-admin"},
		{"bind cluster-admin",
			[]string{cr("r", `- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterrolebindings], verbs: [create]}
- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind], resourceNames: [cluster-admin]}`), crbTo("r", mallory)},
			"bind-role"},
		{"bind without create bindings is not a path",
			[]string{cr("r", `- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind]}`), crbTo("r", mallory)},
			""},
		{"bind edit in namespace then create pod",
			[]string{cr("r", `- {apiGroups: [rbac.authorization.k8s.io], resources: [rolebindings], verbs: [create]}
- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind], resourceNames: [edit]}`), rbTo("prod", "r", mallory)},
			"bind-role,holds-cluster-admin"},
		{"escalate on own clusterrole",
			[]string{cr("r", `- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [escalate, update]}`), crbTo("r", mallory)},
			"escalate-role"},
		{"read token secret",
			[]string{cr("r", `- {apiGroups: [""], resources: [secrets], verbs: [get], resourceNames: [admin-bot-token]}`), rbTo("prod", "r", mallory),
				"kind: Secret\ntype: kubernetes.io/service-account-token\nmetadata: {name: admin-bot-token, namespace: prod, annotations: {kubernetes.io/service-account.name: admin-bot}}"},
			"read-token-secret,holds-cluster-admin"},
		{"read secrets but no token secret exists",
			[]string{cr("r", `- {apiGroups: [""], resources: [secrets], verbs: [get, list]}`), rbTo("prod", "r", mallory)},
			""},
		{"exec into pod running admin SA",
			[]string{cr("r", `- {apiGroups: [""], resources: [pods/exec], verbs: [create]}`), rbTo("prod", "r", mallory),
				"kind: Pod\nmetadata: {name: worker, namespace: prod}\nspec: {serviceAccountName: admin-bot}"},
			"exec-into-pod,holds-cluster-admin"},
		{"exec into pod without automounted token",
			[]string{cr("r", `- {apiGroups: [""], resources: [pods/exec], verbs: [create]}`), rbTo("prod", "r", mallory),
				"kind: Pod\nmetadata: {name: worker, namespace: prod}\nspec: {serviceAccountName: admin-bot, automountServiceAccountToken: false}"},
			""},
		{"nodes/proxy reaches pods (approximate)",
			[]string{cr("r", `- {apiGroups: [""], resources: [nodes/proxy], verbs: [get]}`), crbTo("r", mallory),
				"kind: Pod\nmetadata: {name: worker, namespace: prod}\nspec: {serviceAccountName: admin-bot, nodeName: n1}"},
			"kubelet-nodes-proxy,holds-cluster-admin"},
		{"csr mint certificate",
			[]string{cr("r", `- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests], verbs: [create]}
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests/approval], verbs: [update]}
- {apiGroups: [certificates.k8s.io], resources: [signers], verbs: [approve]}`), crbTo("r", mallory)},
			"csr-mint-cert,holds-cluster-admin"},
		{"multi-hop: impersonate user who can create pods",
			[]string{cr("imp", `- {apiGroups: [""], resources: [users], verbs: [impersonate], resourceNames: [dev]}`), crbTo("imp", mallory),
				cr("r", `- {apiGroups: [""], resources: [pods], verbs: [create]}`), rbTo("prod", "r", "{kind: User, name: dev}")},
			"impersonate,create-pod,holds-cluster-admin"},
		{"read-only user has no path",
			[]string{cr("r", `- {apiGroups: [""], resources: [pods, services], verbs: [get, list, watch]}`), crbTo("r", mallory)},
			""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := build(t, tt.docs...)
			hops := g.Shortest("user:mallory", AdminNode)
			got := techniques(hops)
			if hops == nil {
				got = ""
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestFindDefaultsAndTargets(t *testing.T) {
	g := build(t, cr("r", `- {apiGroups: [""], resources: [pods], verbs: [create]}`), rbTo("prod", "r", mallory))
	ps := g.Find(FindOptions{})
	var srcs []string
	for _, p := range ps {
		srcs = append(srcs, p.Source.String())
	}
	if strings.Join(srcs, " ") != "sa:prod/admin-bot user:mallory" {
		t.Fatalf("sources: %v", srcs)
	}
	// Explicit identity target.
	ps = g.Find(FindOptions{From: []rbac.Identity{rbac.UserID("mallory")}, To: "sa:prod/default"})
	if len(ps) != 1 || techniques(ps[0].Hops) != "create-pod" {
		t.Fatalf("to sa: %+v", ps)
	}
	if g.EdgeCount() == 0 {
		t.Fatal("expected edges")
	}
}

func TestApproximateFlag(t *testing.T) {
	g := build(t, cr("r", `- {apiGroups: [""], resources: [nodes/proxy], verbs: [get]}`), crbTo("r", mallory),
		"kind: Pod\nmetadata: {name: worker, namespace: prod}\nspec: {serviceAccountName: admin-bot}")
	ps := g.Find(FindOptions{From: []rbac.Identity{rbac.UserID("mallory")}})
	if len(ps) != 1 || !ps[0].Approximate() {
		t.Fatalf("expected one approximate path: %+v", ps)
	}
}
