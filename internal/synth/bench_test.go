package synth

import (
	"testing"

	"github.com/Opsbreak/rbacscope/internal/audit"
	"github.com/Opsbreak/rbacscope/internal/loader"
	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/paths"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

func loadDefault(tb testing.TB) *model.Cluster {
	tb.Helper()
	c, err := loader.LoadBytes("synthetic.yaml", Generate(Default))
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

func TestGenerateSize(t *testing.T) {
	c := loadDefault(t)
	if len(c.RoleBindings) != Default.Namespaces*Default.RoleBindingsPerNS {
		t.Fatalf("rolebindings: %d", len(c.RoleBindings))
	}
	if len(c.ClusterRoleBindings) != Default.ClusterRoleBindings {
		t.Fatalf("clusterrolebindings: %d", len(c.ClusterRoleBindings))
	}
	e := rbac.NewEngine(c)
	if len(e.Dangling) != 0 {
		t.Fatalf("unexpected dangling bindings: %d", len(e.Dangling))
	}
	g := paths.Build(e, paths.Options{})
	if len(g.Find(paths.FindOptions{})) == 0 {
		t.Fatal("expected escalation paths in synthetic cluster")
	}
}

func BenchmarkLoadYAML(b *testing.B) {
	data := Generate(Default)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := loader.LoadBytes("synthetic.yaml", data); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewEngine(b *testing.B) {
	c := loadDefault(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rbac.NewEngine(c)
	}
}

func BenchmarkWhoCan(b *testing.B) {
	e := rbac.NewEngine(loadDefault(b))
	q := rbac.WhoCanQuery{Attributes: rbac.Attributes{Verb: "get", Resource: "secrets"}, AllNamespaces: true}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.WhoCan(q)
	}
}

func BenchmarkAudit(b *testing.B) {
	c := loadDefault(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		audit.Run(rbac.NewEngine(c), audit.Options{})
	}
}

func BenchmarkPathsAllSources(b *testing.B) {
	c := loadDefault(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := paths.Build(rbac.NewEngine(c), paths.Options{})
		g.Find(paths.FindOptions{})
	}
}
