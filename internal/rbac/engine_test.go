package rbac_test

import (
	"strings"
	"testing"

	"github.com/Opsbreak/rbacscope/internal/loader"
	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

func engine(t testing.TB, docs ...string) *rbac.Engine {
	t.Helper()
	c, err := loader.LoadBytes("test.yaml", []byte(strings.Join(docs, "\n---\n")))
	if err != nil {
		t.Fatal(err)
	}
	return rbac.NewEngine(c)
}

const aggregationFixture = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: top, labels: {}}
aggregationRule:
  clusterRoleSelectors:
  - matchLabels: {agg-top: "true"}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: mid, labels: {agg-top: "true"}}
aggregationRule:
  clusterRoleSelectors:
  - matchExpressions: [{key: agg-mid, operator: Exists}]
rules:
- {apiGroups: [""], resources: [configmaps], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: leaf, labels: {agg-mid: "yes"}}
rules:
- {apiGroups: [""], resources: [pods], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: other, labels: {agg-mid: "no", unrelated: "x"}}
rules:
- {apiGroups: [""], resources: [secrets], verbs: [list]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: excluded, labels: {something: "else"}}
rules:
- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: cyc-a, labels: {cyc: a}}
aggregationRule:
  clusterRoleSelectors: [{matchLabels: {cyc: b}}]
rules:
- {apiGroups: [""], resources: [services], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: cyc-b, labels: {cyc: b}}
aggregationRule:
  clusterRoleSelectors: [{matchLabels: {cyc: a}}]
rules:
- {apiGroups: [""], resources: [endpoints], verbs: [get]}
`

func hasRule(e *rbac.Engine, role, verb, res string) (bool, string) {
	r := e.ClusterRole(role)
	for _, er := range e.Rules(r) {
		a := rbac.Attributes{Verb: verb, Resource: res}
		if rbac.RuleAllows(a, &er.Rule) {
			return true, er.From.Meta.Name
		}
	}
	return false, ""
}

func TestAggregation(t *testing.T) {
	e := engine(t, aggregationFixture)
	tests := []struct {
		role, verb, res string
		want            bool
		from            string
	}{
		{"mid", "create", "pods", true, "leaf"},      // direct aggregation via Exists
		{"mid", "list", "secrets", true, "other"},    // Exists matches any value
		{"mid", "get", "configmaps", true, "mid"},    // own exported rules kept
		{"top", "create", "pods", true, "leaf"},      // nested aggregation resolved iteratively
		{"top", "get", "configmaps", true, "mid"},    // nested own rules
		{"top", "delete", "nodes", false, ""},        // unrelated wildcard role not aggregated
		{"cyc-a", "get", "endpoints", true, "cyc-b"}, // cycles terminate
		{"cyc-b", "get", "services", true, "cyc-a"},  // cycles terminate both ways
		{"leaf", "list", "secrets", false, ""},       // non-aggregating role unchanged
	}
	for _, tt := range tests {
		t.Run(tt.role+"/"+tt.verb+"/"+tt.res, func(t *testing.T) {
			got, from := hasRule(e, tt.role, tt.verb, tt.res)
			if got != tt.want || (got && from != tt.from) {
				t.Fatalf("got (%v,%s), want (%v,%s)", got, from, tt.want, tt.from)
			}
		})
	}
}

const scopeFixture = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules:
- {apiGroups: [""], resources: [secrets, nodes], verbs: [get, list]}
- {nonResourceURLs: ["/metrics"], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: rb, namespace: team-a}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: secret-reader}
subjects:
- {kind: User, name: alice}
- {kind: ServiceAccount, name: app}
- {kind: Group, name: "system:serviceaccounts:team-b"}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: crb}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: secret-reader}
subjects:
- {kind: Group, name: ops}
- {kind: User, name: "system:serviceaccount:tools:robot"}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: local, namespace: team-a}
rules:
- {apiGroups: [""], resources: [configmaps], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: wrong-ns-role, namespace: team-c}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local}
subjects:
- {kind: User, name: carol}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: local, namespace: team-a}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: local}
subjects:
- {kind: User, name: carol}
`

func TestBindingScopeAndSubjects(t *testing.T) {
	e := engine(t, scopeFixture)
	get := func(res, ns string) rbac.Attributes {
		return rbac.Attributes{Verb: "get", Resource: res, Namespace: ns, Name: "x"}
	}
	tests := []struct {
		name string
		id   rbac.Identity
		a    rbac.Attributes
		want bool
	}{
		{"RoleBinding to ClusterRole grants in its namespace", rbac.UserID("alice"), get("secrets", "team-a"), true},
		{"RoleBinding to ClusterRole not in other namespace", rbac.UserID("alice"), get("secrets", "team-b"), false},
		{"RoleBinding never grants cluster-wide", rbac.UserID("alice"), get("secrets", ""), false},
		{"RoleBinding never grants cluster-scoped resources", rbac.UserID("alice"), get("nodes", ""), false},
		{"RoleBinding never grants non-resource URLs", rbac.UserID("alice"), rbac.Attributes{Verb: "get", Path: "/metrics"}, false},
		{"SA subject without namespace defaults to binding ns", rbac.SAID("team-a", "app"), get("secrets", "team-a"), true},
		{"SA subject defaulting does not match other ns", rbac.SAID("team-c", "app"), get("secrets", "team-a"), false},
		{"system:serviceaccounts:<ns> group matches SAs in ns", rbac.SAID("team-b", "anything"), get("secrets", "team-a"), true},
		{"system:serviceaccounts:<ns> group does not match other ns", rbac.SAID("team-c", "anything"), get("secrets", "team-a"), false},
		{"ClusterRoleBinding grants in every namespace", rbac.GroupID("ops"), get("secrets", "zzz"), true},
		{"ClusterRoleBinding grants cluster-wide", rbac.GroupID("ops"), get("secrets", ""), true},
		{"ClusterRoleBinding grants cluster-scoped", rbac.GroupID("ops"), get("nodes", ""), true},
		{"ClusterRoleBinding grants non-resource", rbac.GroupID("ops"), rbac.Attributes{Verb: "get", Path: "/metrics"}, true},
		{"User subject in SA username form matches SA", rbac.SAID("tools", "robot"), get("secrets", ""), true},
		{"extra group membership applies", rbac.Identity{Kind: model.SubjectUser, Name: "zed", ExtraGroups: []string{"ops"}}, get("secrets", "x"), true},
		{"unbound user", rbac.UserID("mallory"), get("secrets", "team-a"), false},
		{"Role referenced from another namespace is dangling", rbac.UserID("carol"), rbac.Attributes{Verb: "get", Resource: "configmaps", Namespace: "team-c"}, false},
		{"Role in same namespace works", rbac.UserID("carol"), rbac.Attributes{Verb: "get", Resource: "configmaps", Namespace: "team-a"}, true},
		{"system:masters bypass", rbac.GroupID("system:masters"), get("anything", ""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.Allowed(tt.id, tt.a); got != tt.want {
				t.Fatalf("Allowed(%s, %v) = %v, want %v", tt.id, tt.a, got, tt.want)
			}
		})
	}
	if len(e.Dangling) != 1 || e.Dangling[0].Meta.Name != "wrong-ns-role" {
		t.Fatalf("expected one dangling binding, got %v", e.Dangling)
	}
}

func TestWhoCan(t *testing.T) {
	e := engine(t, scopeFixture)
	subjects := func(rows []rbac.WhoCanRow) string {
		var out []string
		for _, r := range rows {
			out = append(out, rbac.IdentityFromSubject(r.Subject).String()+"@"+r.Scope)
		}
		return strings.Join(out, " ")
	}
	tests := []struct {
		name string
		q    rbac.WhoCanQuery
		want string
	}{
		{"namespaced query", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "get", Resource: "secrets", Namespace: "team-a"}},
			"user:alice@ns/team-a sa:tools/robot@cluster-wide group:ops@cluster-wide group:system:serviceaccounts:team-b@ns/team-a sa:team-a/app@ns/team-a"},
		{"other namespace sees only cluster-wide", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "list", Resource: "secrets", Namespace: "zzz"}},
			"sa:tools/robot@cluster-wide group:ops@cluster-wide"},
		{"cluster-scoped resource ignores RoleBindings", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "get", Resource: "nodes"}, AllNamespaces: true},
			"sa:tools/robot@cluster-wide group:ops@cluster-wide"},
		{"all namespaces", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "get", Resource: "configmaps"}, AllNamespaces: true},
			"user:carol@ns/team-a"},
		{"nobody", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "delete", Resource: "secrets"}, AllNamespaces: true}, ""},
		{"non-resource", rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "get", Path: "/metrics"}},
			"sa:tools/robot@cluster-wide group:ops@cluster-wide"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := subjects(e.WhoCan(tt.q)); got != tt.want {
				t.Fatalf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}

func TestParseIdentity(t *testing.T) {
	tests := []struct {
		in, want string
		err      bool
	}{
		{"alice", "user:alice", false},
		{"user:alice", "user:alice", false},
		{"group:dev", "group:dev", false},
		{"sa:ci/runner", "sa:ci/runner", false},
		{"serviceaccount:ci/runner", "sa:ci/runner", false},
		{"system:serviceaccount:ci:runner", "sa:ci/runner", false},
		{"user:system:serviceaccount:ci:runner", "sa:ci/runner", false},
		{"sa:runner", "", true},
		{"group:", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			id, err := rbac.ParseIdentity(tt.in)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v", err)
			}
			if err == nil && id.String() != tt.want {
				t.Fatalf("got %s want %s", id, tt.want)
			}
		})
	}
}

func TestIdentityGroups(t *testing.T) {
	tests := []struct {
		id   rbac.Identity
		want string
	}{
		{rbac.SAID("ns1", "x"), "system:serviceaccounts,system:serviceaccounts:ns1,system:authenticated"},
		{rbac.UserID("bob"), "system:authenticated"},
		{rbac.UserID("system:anonymous"), "system:unauthenticated"},
		{rbac.GroupID("dev"), "dev,system:authenticated"},
		{rbac.GroupID("system:unauthenticated"), "system:unauthenticated"},
	}
	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			if got := strings.Join(tt.id.Groups(), ","); got != tt.want {
				t.Fatalf("got %s want %s", got, tt.want)
			}
		})
	}
}

func TestAccessFor(t *testing.T) {
	e := engine(t, scopeFixture, `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: named, namespace: team-x}
rules:
- {apiGroups: [""], resources: [secrets], resourceNames: [s1, s2], verbs: [get]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: named, namespace: team-x}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: named}
subjects: [{kind: User, name: alice}]
`)
	acc := e.AccessFor(rbac.UserID("alice"), rbac.Attributes{Verb: "get", Resource: "secrets"})
	if acc.ClusterWide {
		t.Fatal("alice must not have cluster-wide access")
	}
	if !acc.InNamespace("team-a") || acc.InNamespace("team-x") {
		t.Fatalf("namespace access wrong: %+v", acc.NS)
	}
	if !acc.AllowsName("team-x", "s2") || acc.AllowsName("team-x", "s3") {
		t.Fatal("resourceNames not honoured")
	}
	if !e.AccessFor(rbac.GroupID("ops"), rbac.Attributes{Verb: "get", Resource: "secrets"}).ClusterWide {
		t.Fatal("ops should have cluster-wide access")
	}
}
