package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/paths"
)

type graphEdge struct {
	from, to, label string
	approx          bool
}

func collect(ps []paths.Path) (nodes []string, edges []graphEdge) {
	seenN := map[string]bool{}
	seenE := map[string]bool{}
	for _, p := range ps {
		for _, h := range p.Hops {
			for _, n := range []string{h.From, h.To} {
				if !seenN[n] {
					seenN[n] = true
					nodes = append(nodes, n)
				}
			}
			k := h.From + "\x00" + h.To
			if seenE[k] {
				continue
			}
			seenE[k] = true
			edges = append(edges, graphEdge{from: h.From, to: h.To, label: string(h.Technique), approx: h.Approximate})
		}
	}
	sort.Strings(nodes)
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].from != edges[j].from {
			return edges[i].from < edges[j].from
		}
		return edges[i].to < edges[j].to
	})
	return nodes, edges
}

func dotQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func nodeShape(n string) string {
	switch {
	case n == paths.AdminNode:
		return `shape=doubleoctagon, style=filled, fillcolor="#f8d7da"`
	case strings.HasPrefix(n, "sa:"):
		return "shape=box"
	case strings.HasPrefix(n, "group:"):
		return "shape=folder"
	}
	return "shape=ellipse"
}

// DOT renders the union of the paths as a Graphviz digraph.
func DOT(w io.Writer, ps []paths.Path) error {
	nodes, edges := collect(ps)
	var b strings.Builder
	b.WriteString("digraph rbacscope {\n  rankdir=LR;\n  node [fontname=\"Helvetica\"];\n  edge [fontname=\"Helvetica\", fontsize=10];\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, "  %s [%s];\n", dotQuote(n), nodeShape(n))
	}
	for _, e := range edges {
		style := ""
		if e.approx {
			style = ", style=dashed"
		}
		fmt.Fprintf(&b, "  %s -> %s [label=%s%s];\n", dotQuote(e.from), dotQuote(e.to), dotQuote(e.label), style)
	}
	b.WriteString("}\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// Mermaid renders the union of the paths as a Mermaid flowchart.
func Mermaid(w io.Writer, ps []paths.Path) error {
	nodes, edges := collect(ps)
	ids := map[string]string{}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, n := range nodes {
		id := fmt.Sprintf("n%d", i)
		ids[n] = id
		label := strings.ReplaceAll(n, `"`, "'")
		switch {
		case n == paths.AdminNode:
			fmt.Fprintf(&b, "  %s{{\"%s\"}}\n", id, label)
		case strings.HasPrefix(n, "sa:"):
			fmt.Fprintf(&b, "  %s[\"%s\"]\n", id, label)
		default:
			fmt.Fprintf(&b, "  %s([\"%s\"])\n", id, label)
		}
	}
	for _, e := range edges {
		arrow := "-->"
		if e.approx {
			arrow = "-.->"
		}
		fmt.Fprintf(&b, "  %s %s|%s| %s\n", ids[e.from], arrow, e.label, ids[e.to])
	}
	if _, ok := ids[paths.AdminNode]; ok {
		fmt.Fprintf(&b, "  style %s fill:#f8d7da,stroke:#c00\n", ids[paths.AdminNode])
	}
	_, err := io.WriteString(w, b.String())
	return err
}
