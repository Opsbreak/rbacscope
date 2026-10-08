package synth

import (
	"testing"

	"github.com/Opsbreak/rbacscope/internal/paths"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

// TestReportScale logs the size of the benchmark cluster (go test -v -run TestReportScale).
func TestReportScale(t *testing.T) {
	c := loadDefault(t)
	e := rbac.NewEngine(c)
	g := paths.Build(e, paths.Options{})
	ps := g.Find(paths.FindOptions{})
	t.Logf("input: %d bytes YAML, %d ClusterRoles, %d Roles, %d ClusterRoleBindings, %d RoleBindings, %d ServiceAccounts, %d workloads, %d namespaces",
		len(Generate(Default)), len(c.ClusterRoles), len(c.Roles), len(c.ClusterRoleBindings), len(c.RoleBindings), len(c.ServiceAccounts), len(c.Pods), len(e.Namespaces()))
	t.Logf("graph: %d nodes, %d edges, %d sources with a path to cluster-admin", len(g.Nodes), g.EdgeCount(), len(ps))
}
