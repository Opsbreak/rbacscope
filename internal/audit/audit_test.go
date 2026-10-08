package audit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Opsbreak/rbacscope/internal/loader"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

func clusterRole(name, rules string) string {
	return fmt.Sprintf("kind: ClusterRole\nmetadata: {name: %s}\nrules:\n%s", name, rules)
}

func role(ns, name, rules string) string {
	return fmt.Sprintf("kind: Role\nmetadata: {name: %s, namespace: %s}\nrules:\n%s", name, ns, rules)
}

func crb(name, roleName, subject string) string {
	return fmt.Sprintf("kind: ClusterRoleBinding\nmetadata: {name: %s}\nroleRef: {kind: ClusterRole, name: %s}\nsubjects: [%s]", name, roleName, subject)
}

func rb(ns, name, roleKind, roleName, subject string) string {
	return fmt.Sprintf("kind: RoleBinding\nmetadata: {name: %s, namespace: %s}\nroleRef: {kind: %s, name: %s}\nsubjects: [%s]", name, ns, roleKind, roleName, subject)
}

const alice = "{kind: User, name: alice}"

func run(t *testing.T, opts Options, docs ...string) []Finding {
	t.Helper()
	c, err := loader.LoadBytes("t.yaml", []byte(strings.Join(docs, "\n---\n")))
	if err != nil {
		t.Fatal(err)
	}
	return Run(rbac.NewEngine(c), opts)
}

// none marks "rule must not fire".
const none Severity = -1

func TestRules(t *testing.T) {
	r := func(rules string) string { return clusterRole("r", rules) }
	bindCW := crb("b", "r", alice)
	bindNS := rb("team", "b", "ClusterRole", "r", alice)
	tests := []struct {
		name string
		rule string
		want Severity
		docs []string
	}{
		// RS001
		{"RS001 full wildcard cluster-wide", "RS001", Critical, []string{r(`- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`), bindCW}},
		{"RS001 full wildcard namespaced", "RS001", High, []string{r(`- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`), bindNS}},
		{"RS001 negative: resourceNames restricted", "RS001", none, []string{r(`- {apiGroups: ["*"], resources: ["*"], verbs: ["*"], resourceNames: [x]}`), bindCW}},
		{"RS001 negative: system binding skipped by default", "RS001", none, []string{r(`- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`), crb("system:x", "r", alice)}},
		// RS002
		{"RS002 wildcard verbs", "RS002", Medium, []string{r(`- {apiGroups: [""], resources: [configmaps], verbs: ["*"]}`), bindCW}},
		{"RS002 wildcard resources namespaced", "RS002", Low, []string{r(`- {apiGroups: [""], resources: ["*"], verbs: [get]}`), bindNS}},
		{"RS002 negative: explicit rule", "RS002", none, []string{r(`- {apiGroups: [""], resources: [configmaps], verbs: [get]}`), bindCW}},
		// RS003
		{"RS003 bind clusterroles", "RS003", Critical, []string{r(`- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind]}`), bindCW}},
		{"RS003 escalate roles namespaced", "RS003", High, []string{r(`- {apiGroups: [rbac.authorization.k8s.io], resources: [roles], verbs: [escalate]}`), bindNS}},
		{"RS003 bind restricted by name", "RS003", High, []string{r(`- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind], resourceNames: [view]}`), bindCW}},
		{"RS003 negative: create roles only", "RS003", none, []string{r(`- {apiGroups: [rbac.authorization.k8s.io], resources: [roles, clusterroles], verbs: [create, update]}`), bindCW}},
		// RS004
		{"RS004 impersonate users", "RS004", Critical, []string{r(`- {apiGroups: [""], resources: [users], verbs: [impersonate]}`), bindCW}},
		{"RS004 impersonate serviceaccounts namespaced", "RS004", High, []string{r(`- {apiGroups: [""], resources: [serviceaccounts], verbs: [impersonate]}`), bindNS}},
		{"RS004 restricted to system:masters stays critical", "RS004", Critical, []string{r(`- {apiGroups: [""], resources: [groups], verbs: [impersonate], resourceNames: ["system:masters"]}`), bindCW}},
		{"RS004 negative: impersonate users via RoleBinding is ineffective", "RS004", none, []string{r(`- {apiGroups: [""], resources: [users], verbs: [impersonate]}`), bindNS}},
		// RS005
		{"RS005 create pods namespaced", "RS005", High, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [create]}`), bindNS}},
		{"RS005 patch deployments cluster-wide", "RS005", Critical, []string{r(`- {apiGroups: [apps], resources: [deployments], verbs: [patch]}`), bindCW}},
		{"RS005 namespace with admin SA escalates to critical", "RS005", Critical, []string{
			r(`- {apiGroups: [""], resources: [pods], verbs: [create]}`), bindNS,
			crb("adm", "cluster-admin", "{kind: ServiceAccount, name: robot, namespace: team}"),
			clusterRole("cluster-admin", `- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`)}},
		{"RS005 negative: create pods restricted by name never works", "RS005", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [create], resourceNames: [x]}`), bindCW}},
		{"RS005 negative: wrong api group", "RS005", none, []string{r(`- {apiGroups: [""], resources: [deployments], verbs: [create]}`), bindCW}},
		// RS006
		{"RS006 pods/exec namespaced", "RS006", High, []string{r(`- {apiGroups: [""], resources: [pods/exec], verbs: [create]}`), bindNS}},
		{"RS006 pods/attach cluster-wide", "RS006", Critical, []string{r(`- {apiGroups: [""], resources: [pods/attach], verbs: [create]}`), bindCW}},
		{"RS006 negative: pods does not include pods/exec", "RS006", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [create, get]}`), bindNS}},
		// RS007
		{"RS007 nodes/proxy", "RS007", Critical, []string{r(`- {apiGroups: [""], resources: [nodes/proxy], verbs: [get]}`), bindCW}},
		{"RS007 via */proxy", "RS007", Critical, []string{r(`- {apiGroups: [""], resources: ["*/proxy"], verbs: [create]}`), bindCW}},
		{"RS007 negative: RoleBinding cannot grant nodes", "RS007", none, []string{r(`- {apiGroups: [""], resources: [nodes/proxy], verbs: [get]}`), bindNS}},
		{"RS007 negative: nodes/metrics", "RS007", none, []string{r(`- {apiGroups: [""], resources: [nodes/metrics], verbs: [get]}`), bindCW}},
		// RS008
		{"RS008 cluster-wide list secrets", "RS008", Critical, []string{r(`- {apiGroups: [""], resources: [secrets], verbs: [list]}`), bindCW}},
		{"RS008 namespaced get secrets", "RS008", High, []string{r(`- {apiGroups: [""], resources: [secrets], verbs: [get]}`), bindNS}},
		{"RS008 named secret", "RS008", Low, []string{r(`- {apiGroups: [""], resources: [secrets], verbs: [get], resourceNames: [db]}`), bindNS}},
		{"RS008 negative: create secrets only", "RS008", none, []string{r(`- {apiGroups: [""], resources: [secrets], verbs: [create, delete]}`), bindCW}},
		// RS009
		{"RS009 token create cluster-wide", "RS009", Critical, []string{r(`- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create]}`), bindCW}},
		{"RS009 token create named", "RS009", Medium, []string{r(`- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create], resourceNames: [bot]}`), bindNS}},
		{"RS009 negative: serviceaccounts create", "RS009", none, []string{r(`- {apiGroups: [""], resources: [serviceaccounts], verbs: [create]}`), bindCW}},
		// RS010
		{"RS010 csr create+approve+signer", "RS010", Critical, []string{r(`
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests], verbs: [create]}
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests/approval], verbs: [update]}
- {apiGroups: [certificates.k8s.io], resources: [signers], verbs: [approve], resourceNames: [kubernetes.io/kube-apiserver-client]}`), bindCW}},
		{"RS010 without signer approve is medium", "RS010", Medium, []string{r(`
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests], verbs: [create]}
- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests/approval], verbs: [update]}`), bindCW}},
		{"RS010 negative: create only", "RS010", none, []string{r(`- {apiGroups: [certificates.k8s.io], resources: [certificatesigningrequests], verbs: [create]}`), bindCW}},
		// RS011
		{"RS011 mutating webhooks", "RS011", Critical, []string{r(`- {apiGroups: [admissionregistration.k8s.io], resources: [mutatingwebhookconfigurations], verbs: [patch]}`), bindCW}},
		{"RS011 validating webhooks", "RS011", High, []string{r(`- {apiGroups: [admissionregistration.k8s.io], resources: [validatingwebhookconfigurations], verbs: [create]}`), bindCW}},
		{"RS011 negative: read only", "RS011", none, []string{r(`- {apiGroups: [admissionregistration.k8s.io], resources: [mutatingwebhookconfigurations], verbs: [get, list]}`), bindCW}},
		// RS012
		{"RS012 create persistentvolumes", "RS012", High, []string{r(`- {apiGroups: [""], resources: [persistentvolumes], verbs: [create]}`), bindCW}},
		{"RS012 negative: persistentvolumeclaims", "RS012", none, []string{r(`- {apiGroups: [""], resources: [persistentvolumeclaims], verbs: [create]}`), bindCW}},
		// RS013
		{"RS013 unauthenticated", "RS013", Critical, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`), crb("b", "r", "{kind: Group, name: \"system:unauthenticated\"}")}},
		{"RS013 authenticated", "RS013", High, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`), crb("b", "r", "{kind: Group, name: \"system:authenticated\"}")}},
		{"RS013 non-resource only is low", "RS013", Low, []string{r(`- {nonResourceURLs: [/healthz], verbs: [get]}`), crb("b", "r", "{kind: Group, name: \"system:unauthenticated\"}")}},
		{"RS013 negative: specific group", "RS013", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`), crb("b", "r", "{kind: Group, name: devs}")}},
		// RS014
		{"RS014 default SA bound and automounted", "RS014", Medium, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`),
			rb("team", "b", "ClusterRole", "r", "{kind: ServiceAccount, name: default}"),
			"kind: Pod\nmetadata: {name: p, namespace: team}\nspec: {containers: [{name: c}]}"}},
		{"RS014 negative: automount disabled on SA", "RS014", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`),
			rb("team", "b", "ClusterRole", "r", "{kind: ServiceAccount, name: default}"),
			"kind: ServiceAccount\nmetadata: {name: default, namespace: team}\nautomountServiceAccountToken: false",
			"kind: Pod\nmetadata: {name: p, namespace: team}\nspec: {containers: [{name: c}]}"}},
		{"RS014 negative: pod uses dedicated SA", "RS014", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`),
			rb("team", "b", "ClusterRole", "r", "{kind: ServiceAccount, name: default}"),
			"kind: Pod\nmetadata: {name: p, namespace: team}\nspec: {serviceAccountName: app}"}},
		// RS015
		{"RS015 cluster-admin inventory includes system bindings", "RS015", Info, []string{clusterRole("cluster-admin", `- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`),
			crb("system:masters-admin", "cluster-admin", "{kind: Group, name: \"system:masters\"}")}},
		{"RS015 negative: no admin bindings", "RS015", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`), bindCW}},
		// RS016
		{"RS016 dangling", "RS016", Low, []string{crb("b", "missing", alice)}},
		{"RS016 negative: role exists", "RS016", none, []string{r(`- {apiGroups: [""], resources: [pods], verbs: [list]}`), bindCW}},
		// RS017
		{"RS017 pod with admin SA", "RS017", High, []string{clusterRole("cluster-admin", `- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`),
			crb("adm", "cluster-admin", "{kind: ServiceAccount, name: robot, namespace: team}"),
			"kind: Deployment\nmetadata: {name: d, namespace: team}\nspec: {template: {spec: {serviceAccountName: robot}}}"}},
		{"RS017 negative: automount disabled on pod", "RS017", none, []string{clusterRole("cluster-admin", `- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}`),
			crb("adm", "cluster-admin", "{kind: ServiceAccount, name: robot, namespace: team}"),
			"kind: Deployment\nmetadata: {name: d, namespace: team}\nspec: {template: {spec: {serviceAccountName: robot, automountServiceAccountToken: false}}}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := run(t, Options{}, tt.docs...)
			var got []Finding
			for _, f := range fs {
				if f.RuleID == tt.rule {
					got = append(got, f)
				}
			}
			if tt.want == none {
				if len(got) > 0 {
					t.Fatalf("expected no %s finding, got %+v", tt.rule, got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("expected %s finding; all findings: %+v", tt.rule, fs)
			}
			if got[0].Severity != tt.want {
				t.Fatalf("%s severity = %s, want %s (%s)", tt.rule, got[0].Severity, tt.want, got[0].Message)
			}
			if got[0].Location.File != "t.yaml" {
				t.Fatalf("missing location: %+v", got[0].Location)
			}
		})
	}
}

func TestIncludeSystem(t *testing.T) {
	docs := []string{clusterRole("r", `- {apiGroups: [""], resources: [secrets], verbs: [list]}`), crb("system:controller", "r", alice)}
	if fs := run(t, Options{}, docs...); len(fs) != 0 {
		t.Fatalf("system binding should be skipped: %+v", fs)
	}
	if fs := run(t, Options{IncludeSystem: true}, docs...); len(fs) != 1 || fs[0].RuleID != "RS008" {
		t.Fatalf("system binding should be audited with IncludeSystem: %+v", fs)
	}
}

func TestSortAndFilter(t *testing.T) {
	fs := run(t, Options{},
		clusterRole("r", `- {apiGroups: [""], resources: [secrets], verbs: [list]}
- {apiGroups: [""], resources: [configmaps], verbs: ["*"]}`),
		crb("b", "r", alice), crb("dangling", "nope", alice))
	if len(fs) != 3 || fs[0].Severity != Critical || fs[len(fs)-1].Severity != Low {
		t.Fatalf("unexpected order: %+v", fs)
	}
	if len(Filter(fs, High)) != 1 {
		t.Fatal("filter failed")
	}
	if m, ok := Max(fs); !ok || m != Critical {
		t.Fatal("max failed")
	}
	if fs[0].Fingerprint == "" || fs[0].Fingerprint == fs[1].Fingerprint {
		t.Fatal("fingerprints must be set and distinct")
	}
}

func TestParseSeverity(t *testing.T) {
	for i, n := range []string{"info", "LOW", "Medium", "high", "critical"} {
		s, err := ParseSeverity(n)
		if err != nil || int(s) != i {
			t.Fatalf("%s: %v %v", n, s, err)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRuleCatalogue(t *testing.T) {
	seen := map[string]bool{}
	for i, r := range Rules {
		want := fmt.Sprintf("RS%03d", i+1)
		if r.ID != want || seen[r.ID] || r.Title == "" || r.Remediation == "" || r.Description == "" {
			t.Fatalf("bad rule entry %d: %+v", i, r)
		}
		seen[r.ID] = true
	}
}
