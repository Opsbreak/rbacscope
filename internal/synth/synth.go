// Package synth generates large synthetic clusters (as manifest YAML) for
// benchmarks. Output is deterministic for a given Config.
package synth

import (
	"bytes"
	"fmt"
	"math/rand"
)

// Config sizes the generated cluster.
type Config struct {
	Namespaces           int
	RoleBindingsPerNS    int
	ServiceAccountsPerNS int
	PodsPerNS            int
	ClusterRoleBindings  int
	Users                int
	Groups               int
	Seed                 int64
}

// Default is a cluster with 5,000 RoleBindings and 200 ClusterRoleBindings.
var Default = Config{
	Namespaces: 250, RoleBindingsPerNS: 20, ServiceAccountsPerNS: 8, PodsPerNS: 6,
	ClusterRoleBindings: 200, Users: 500, Groups: 50, Seed: 1,
}

var clusterRoleRules = []string{
	`- {apiGroups: [""], resources: [pods, services, configmaps], verbs: [get, list, watch]}`,
	`- {apiGroups: [""], resources: [pods], verbs: [create, delete]}
- {apiGroups: [apps], resources: [deployments], verbs: [get, list, patch]}`,
	`- {apiGroups: [""], resources: [secrets], verbs: [get]}`,
	`- {apiGroups: [""], resources: [pods/exec, pods/attach], verbs: [create]}`,
	`- {apiGroups: [""], resources: [serviceaccounts/token], verbs: [create]}`,
	`- {apiGroups: [rbac.authorization.k8s.io], resources: [rolebindings], verbs: [create]}
- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind], resourceNames: [view-%d]}`,
	`- {apiGroups: [batch], resources: [jobs, cronjobs], verbs: ["*"]}`,
	`- {apiGroups: [""], resources: [users], verbs: [impersonate], resourceNames: [user-%d]}`,
}

// Generate renders the cluster as multi-document YAML.
func Generate(c Config) []byte {
	r := rand.New(rand.NewSource(c.Seed))
	var b bytes.Buffer
	doc := func(format string, a ...interface{}) {
		fmt.Fprintf(&b, format, a...)
		b.WriteString("\n---\n")
	}
	doc("kind: ClusterRole\nmetadata: {name: cluster-admin}\nrules:\n- {apiGroups: [\"*\"], resources: [\"*\"], verbs: [\"*\"]}")
	nRoles := 50
	for i := 0; i < nRoles; i++ {
		tmpl := clusterRoleRules[i%len(clusterRoleRules)]
		rules := tmpl
		if bytes.Contains([]byte(tmpl), []byte("%d")) {
			rules = fmt.Sprintf(tmpl, r.Intn(c.Users))
		}
		doc("kind: ClusterRole\nmetadata: {name: role-%d, labels: {tier: t%d}}\nrules:\n%s", i, i%5, rules)
		if i%10 == 0 {
			doc("kind: ClusterRole\nmetadata: {name: view-%d}\naggregationRule:\n  clusterRoleSelectors: [{matchLabels: {tier: t%d}}]", i, i%5)
		}
	}
	subject := func(ns string) string {
		switch r.Intn(3) {
		case 0:
			return fmt.Sprintf("{kind: User, name: user-%d}", r.Intn(c.Users))
		case 1:
			return fmt.Sprintf("{kind: Group, name: group-%d}", r.Intn(c.Groups))
		}
		if ns == "" {
			ns = fmt.Sprintf("ns-%d", r.Intn(c.Namespaces))
		}
		return fmt.Sprintf("{kind: ServiceAccount, name: sa-%d, namespace: %s}", r.Intn(c.ServiceAccountsPerNS), ns)
	}
	for i := 0; i < c.ClusterRoleBindings; i++ {
		role := fmt.Sprintf("role-%d", r.Intn(nRoles))
		if i%97 == 0 {
			role = "cluster-admin"
		}
		doc("kind: ClusterRoleBinding\nmetadata: {name: crb-%d}\nroleRef: {kind: ClusterRole, name: %s}\nsubjects: [%s, %s]", i, role, subject(""), subject(""))
	}
	for n := 0; n < c.Namespaces; n++ {
		ns := fmt.Sprintf("ns-%d", n)
		doc("kind: Namespace\nmetadata: {name: %s}", ns)
		for s := 0; s < c.ServiceAccountsPerNS; s++ {
			doc("kind: ServiceAccount\nmetadata: {name: sa-%d, namespace: %s}", s, ns)
		}
		doc("kind: Role\nmetadata: {name: local, namespace: %s}\nrules:\n- {apiGroups: [\"\"], resources: [configmaps, secrets], verbs: [get, list]}", ns)
		for p := 0; p < c.PodsPerNS; p++ {
			doc("kind: Deployment\nmetadata: {name: app-%d, namespace: %s}\nspec: {template: {spec: {serviceAccountName: sa-%d}}}", p, ns, r.Intn(c.ServiceAccountsPerNS))
		}
		doc("kind: Secret\ntype: kubernetes.io/service-account-token\nmetadata: {name: sa-0-token, namespace: %s, annotations: {kubernetes.io/service-account.name: sa-0}}", ns)
		for i := 0; i < c.RoleBindingsPerNS; i++ {
			kind, name := "ClusterRole", fmt.Sprintf("role-%d", r.Intn(nRoles))
			if i%7 == 0 {
				kind, name = "Role", "local"
			}
			doc("kind: RoleBinding\nmetadata: {name: rb-%d, namespace: %s}\nroleRef: {kind: %s, name: %s}\nsubjects: [%s]", i, ns, kind, name, subject(ns))
		}
	}
	return b.Bytes()
}
