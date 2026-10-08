// Command rbacscope analyses Kubernetes RBAC manifests offline: who-can
// queries, effective permissions, risk audit and privilege-escalation paths.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/audit"
	"github.com/Opsbreak/rbacscope/internal/loader"
	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/paths"
	"github.com/Opsbreak/rbacscope/internal/rbac"
	"github.com/Opsbreak/rbacscope/internal/report"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitFindings = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `rbacscope - Kubernetes RBAC effective-permissions & privilege-escalation analyzer

Usage:
  rbacscope who-can VERB RESOURCE[/SUBRESOURCE] [-n NS] [--name NAME] -f PATH...
  rbacscope who-can VERB /NON-RESOURCE-URL -f PATH...
  rbacscope can SUBJECT [VERB RESOURCE[/SUB]] [-n NS] [--name NAME] [--group G] -f PATH...
  rbacscope audit [--fail-on SEV] [--min-severity SEV] [-o text|json|sarif] -f PATH...
  rbacscope paths [--from SUBJECT]... [--to cluster-admin|SUBJECT] [-o text|json|dot|mermaid] -f PATH...
  rbacscope rules
  rbacscope version

Subjects:  alice | user:alice   group:dev   sa:NAMESPACE/NAME   system:serviceaccount:NS:NAME

Input (-f, repeatable): files or directories of YAML/JSON manifests, including
"kind: List" output of kubectl get -o yaml. Use "-" for stdin.

Exit codes: 0 ok, 1 error, 2 usage error, 3 findings at or above --fail-on.
`

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

type common struct {
	files  stringList
	output string
	quiet  bool
}

func (c *common) register(fs *flag.FlagSet, formats string) {
	fs.Var(&c.files, "f", "manifest file or directory (repeatable)")
	fs.Var(&c.files, "file", "alias for -f")
	fs.StringVar(&c.output, "o", "text", "output format: "+formats)
	fs.StringVar(&c.output, "output", "text", "alias for -o")
	fs.BoolVar(&c.quiet, "q", false, "suppress loader warnings")
}

// parseInterspersed parses flags that may appear before, between or after
// positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		if rest[0] == "--" {
			return append(pos, rest[1:]...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usagef(format string, a ...interface{}) error { return usageError{fmt.Sprintf(format, a...)} }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	var code int
	var err error
	switch cmd {
	case "who-can", "whocan":
		code, err = cmdWhoCan(rest, stdout, stderr)
	case "can":
		code, err = cmdCan(rest, stdout, stderr)
	case "audit":
		code, err = cmdAudit(rest, stdout, stderr)
	case "paths":
		code, err = cmdPaths(rest, stdout, stderr)
	case "rules":
		code, err = cmdRules(rest, stdout)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "rbacscope %s\n", version)
		return exitOK
	case "help", "-h", "--help", "-help":
		fmt.Fprint(stdout, usage)
		return exitOK
	default:
		fmt.Fprintf(stderr, "rbacscope: unknown command %q\n\n%s", cmd, usage)
		return exitUsage
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) || errors.Is(err, flag.ErrHelp) {
			if !errors.Is(err, flag.ErrHelp) {
				fmt.Fprintf(stderr, "rbacscope %s: %v\n", cmd, err)
			}
			return exitUsage
		}
		fmt.Fprintf(stderr, "rbacscope %s: %v\n", cmd, err)
		return exitError
	}
	return code
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func load(c *common, stderr io.Writer) (*rbac.Engine, error) {
	if len(c.files) == 0 {
		return nil, usagef("no input: pass manifests with -f FILE|DIR (repeatable)")
	}
	cl, err := loader.LoadPaths(c.files)
	if err != nil {
		return nil, err
	}
	if !c.quiet {
		for _, w := range cl.Warnings {
			fmt.Fprintf(stderr, "warning: %s\n", w)
		}
	}
	return rbac.NewEngine(cl), nil
}

func checkFormat(f string, allowed ...string) error {
	for _, a := range allowed {
		if f == a {
			return nil
		}
	}
	return usagef("unsupported output format %q (want %s)", f, strings.Join(allowed, "|"))
}

// parseRequest builds request attributes from VERB RESOURCE.
func parseRequest(verb, res, group, ns, name string) (rbac.Attributes, bool, string, error) {
	if strings.HasPrefix(res, "/") {
		return rbac.Attributes{Verb: verb, Path: res}, true, "", nil
	}
	r, sub, g, known := rbac.ResolveResource(res, group)
	if r == "" {
		return rbac.Attributes{}, false, "", usagef("invalid resource %q", res)
	}
	note := ""
	if !known {
		note = fmt.Sprintf("note: resource %q is not a known built-in; assuming the core API group (use --api-group or RESOURCE.GROUP)", r)
	}
	a := rbac.Attributes{Verb: verb, APIGroup: g, Resource: r, Subresource: sub, Name: name, Namespace: ns}
	clusterScoped := rbac.ClusterScopedRequest(a)
	if clusterScoped {
		a.Namespace = ""
	}
	return a, clusterScoped, note, nil
}

func cmdWhoCan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("who-can", stderr)
	var c common
	c.register(fs, "text|json")
	ns := fs.String("n", "", "namespace (default: all namespaces)")
	fs.StringVar(ns, "namespace", "", "alias for -n")
	name := fs.String("name", "", "object name (resourceNames matching)")
	group := fs.String("api-group", "", `API group of the resource ("core" for the core group)`)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 2 {
		return 0, usagef("expected VERB RESOURCE, got %d argument(s)", len(pos))
	}
	if err := checkFormat(c.output, "text", "json"); err != nil {
		return 0, err
	}
	a, clusterScoped, note, err := parseRequest(pos[0], pos[1], *group, *ns, *name)
	if err != nil {
		return 0, err
	}
	e, err := load(&c, stderr)
	if err != nil {
		return 0, err
	}
	if note != "" && !c.quiet {
		fmt.Fprintln(stderr, note)
	}
	q := rbac.WhoCanQuery{Attributes: a, AllNamespaces: !clusterScoped && *ns == ""}
	rows := e.WhoCan(q)
	if c.output == "json" {
		type out struct {
			Request string           `json:"request"`
			Scope   string           `json:"scope"`
			Results []rbac.WhoCanRow `json:"results"`
		}
		if rows == nil {
			rows = []rbac.WhoCanRow{}
		}
		return exitOK, report.JSON(stdout, out{Request: a.String(), Scope: queryScope(q, clusterScoped), Results: rows})
	}
	fmt.Fprintf(stdout, "Who can %s (%s):\n\n", a.String(), queryScope(q, clusterScoped))
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "No subjects found.")
	} else {
		t := &report.Table{Header: []string{"SUBJECT", "SCOPE", "BINDING", "ROLE", "NOTES"}}
		for _, r := range rows {
			var notes []string
			if len(r.Names) > 0 {
				notes = append(notes, "only names: "+strings.Join(r.Names, ","))
			}
			if r.RuleFrom != "" {
				notes = append(notes, "rule from "+r.RuleFrom)
			}
			t.Add(rbac.IdentityFromSubject(r.Subject).String(), r.Scope, r.Binding, r.Role, strings.Join(notes, "; "))
		}
		if err := t.Write(stdout); err != nil {
			return 0, err
		}
	}
	fmt.Fprintln(stdout, "\nMembers of system:masters are always allowed (the API server bypasses RBAC for them).")
	return exitOK, nil
}

func queryScope(q rbac.WhoCanQuery, clusterScoped bool) string {
	switch {
	case clusterScoped:
		return "cluster-scoped request"
	case q.AllNamespaces:
		return "any namespace"
	}
	return "namespace " + q.Namespace
}

func cmdCan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("can", stderr)
	var c common
	c.register(fs, "text|json")
	ns := fs.String("n", "", "namespace for a VERB RESOURCE check (default: report all namespaces)")
	fs.StringVar(ns, "namespace", "", "alias for -n")
	name := fs.String("name", "", "object name for a VERB RESOURCE check")
	group := fs.String("api-group", "", `API group of the resource ("core" for the core group)`)
	var groups stringList
	fs.Var(&groups, "group", "additional group membership of the subject (repeatable)")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 1 && len(pos) != 3 {
		return 0, usagef("expected SUBJECT [VERB RESOURCE]")
	}
	if err := checkFormat(c.output, "text", "json"); err != nil {
		return 0, err
	}
	id, err := rbac.ParseIdentity(pos[0])
	if err != nil {
		return 0, usagef("%v", err)
	}
	id.ExtraGroups = groups
	e, err := load(&c, stderr)
	if err != nil {
		return 0, err
	}
	if len(pos) == 3 {
		return canCheck(e, id, pos[1], pos[2], *group, *ns, *name, &c, stdout, stderr)
	}
	rows := e.Permissions(id)
	isAdmin := e.IsClusterAdmin(id)
	if c.output == "json" {
		type out struct {
			Subject      string               `json:"subject"`
			Username     string               `json:"username,omitempty"`
			Groups       []string             `json:"groups"`
			ClusterAdmin bool                 `json:"clusterAdminEquivalent"`
			Permissions  []rbac.PermissionRow `json:"permissions"`
		}
		if rows == nil {
			rows = []rbac.PermissionRow{}
		}
		return exitOK, report.JSON(stdout, out{Subject: id.String(), Username: id.Username(), Groups: id.Groups(), ClusterAdmin: isAdmin, Permissions: rows})
	}
	fmt.Fprintf(stdout, "Subject:  %s\n", id.String())
	if u := id.Username(); u != "" {
		fmt.Fprintf(stdout, "Username: %s\n", u)
	}
	fmt.Fprintf(stdout, "Groups:   %s\n", strings.Join(id.Groups(), ", "))
	fmt.Fprintf(stdout, "Cluster-admin equivalent: %s\n\n", yesNo(isAdmin))
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "No RBAC permissions granted.")
		return exitOK, nil
	}
	t := &report.Table{Header: []string{"SCOPE", "VERBS", "APIGROUPS", "RESOURCES", "NAMES", "GRANTED BY"}}
	for _, r := range rows {
		res := report.Join(r.Rule.Resources)
		groups := report.Join(r.Rule.APIGroups)
		if len(r.Rule.NonResourceURLs) > 0 && len(r.Rule.Resources) == 0 {
			res = "urls: " + strings.Join(r.Rule.NonResourceURLs, ",")
			groups = "-"
		}
		via := r.Binding + " -> " + r.Role
		if r.RuleFrom != "" {
			via += " (from " + r.RuleFrom + ")"
		}
		if r.Via != id.String() {
			via += " [as " + r.Via + "]"
		}
		t.Add(r.Scope, strings.Join(r.Rule.Verbs, ","), groups, res, report.Join(r.Rule.ResourceNames), via)
	}
	return exitOK, t.Write(stdout)
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}

func canCheck(e *rbac.Engine, id rbac.Identity, verb, res, group, ns, name string, c *common, stdout, stderr io.Writer) (int, error) {
	a, clusterScoped, note, err := parseRequest(verb, res, group, ns, name)
	if err != nil {
		return 0, err
	}
	if note != "" && !c.quiet {
		fmt.Fprintln(stderr, note)
	}
	type evidence struct {
		Scope   string           `json:"scope"`
		Binding string           `json:"binding"`
		Role    string           `json:"role"`
		Rule    model.PolicyRule `json:"rule"`
		Names   []string         `json:"resourceNames,omitempty"`
	}
	type result struct {
		Subject    string     `json:"subject"`
		Request    string     `json:"request"`
		Where      string     `json:"where"`
		Allowed    bool       `json:"allowed"`
		Superuser  bool       `json:"superuser,omitempty"`
		Namespaces []string   `json:"namespaces,omitempty"`
		Evidence   []evidence `json:"evidence"`
	}
	r := result{Subject: id.String(), Request: a.String(), Evidence: []evidence{}}
	super := false
	for _, g := range id.Groups() {
		if g == rbac.GroupMasters {
			super = true
		}
	}
	r.Superuser = super
	if clusterScoped || ns != "" {
		r.Where = "namespace " + ns
		if clusterScoped {
			r.Where = "cluster scope"
		}
		for _, m := range e.Authorize(id, a) {
			r.Evidence = append(r.Evidence, evidence{Scope: m.Grant.Scope(), Binding: m.Grant.Binding.Ref(), Role: m.Grant.Role.Ref(), Rule: m.Rule.Rule})
		}
		r.Allowed = super || len(r.Evidence) > 0
	} else {
		r.Where = "any namespace"
		acc := e.AccessFor(id, a)
		for _, m := range acc.Matches {
			ev := evidence{Scope: m.Grant.Scope(), Binding: m.Grant.Binding.Ref(), Role: m.Grant.Role.Ref(), Rule: m.Rule.Rule}
			if m.Restricted {
				ev.Names = m.Rule.Rule.ResourceNames
			}
			r.Evidence = append(r.Evidence, ev)
		}
		if acc.ClusterWide {
			r.Namespaces = []string{"*"}
		} else {
			for n := range acc.NS {
				r.Namespaces = append(r.Namespaces, n)
			}
			sort.Strings(r.Namespaces)
		}
		r.Allowed = super || acc.Any()
	}
	if c.output == "json" {
		return exitOK, report.JSON(stdout, r)
	}
	fmt.Fprintf(stdout, "can %s %s (%s)? %s\n", r.Subject, a.String(), r.Where, yesNo(r.Allowed))
	if super {
		fmt.Fprintln(stdout, "  member of system:masters: RBAC is bypassed")
	}
	if len(r.Namespaces) > 0 {
		fmt.Fprintf(stdout, "  namespaces: %s\n", strings.Join(r.Namespaces, ", "))
	}
	for _, ev := range r.Evidence {
		line := fmt.Sprintf("  %s: %s -> %s", ev.Scope, ev.Binding, ev.Role)
		if len(ev.Names) > 0 {
			line += " (only names: " + strings.Join(ev.Names, ",") + ")"
		}
		fmt.Fprintln(stdout, line)
	}
	return exitOK, nil
}

func cmdAudit(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("audit", stderr)
	var c common
	c.register(fs, "text|json|sarif")
	failOn := fs.String("fail-on", "", "exit with code 3 if any finding is at or above this severity (info|low|medium|high|critical)")
	minSev := fs.String("min-severity", "info", "only report findings at or above this severity")
	includeSystem := fs.Bool("include-system", false, "also audit built-in system:/kubeadm: bootstrap bindings")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 0 {
		return 0, usagef("unexpected arguments: %s", strings.Join(pos, " "))
	}
	if err := checkFormat(c.output, "text", "json", "sarif"); err != nil {
		return 0, err
	}
	minLevel, err := audit.ParseSeverity(*minSev)
	if err != nil {
		return 0, usagef("%v", err)
	}
	var fail *audit.Severity
	if *failOn != "" {
		s, err := audit.ParseSeverity(*failOn)
		if err != nil {
			return 0, usagef("%v", err)
		}
		fail = &s
	}
	e, err := load(&c, stderr)
	if err != nil {
		return 0, err
	}
	findings := audit.Filter(audit.Run(e, audit.Options{IncludeSystem: *includeSystem}), minLevel)
	switch c.output {
	case "json":
		type out struct {
			Version  string          `json:"version"`
			Summary  map[string]int  `json:"summary"`
			Findings []audit.Finding `json:"findings"`
		}
		if findings == nil {
			findings = []audit.Finding{}
		}
		err = report.JSON(stdout, out{Version: version, Summary: summary(findings), Findings: findings})
	case "sarif":
		err = report.SARIF(stdout, version, findings)
	default:
		err = writeAuditText(stdout, findings)
	}
	if err != nil {
		return 0, err
	}
	if fail != nil {
		if worst, found := audit.Max(findings); found && worst >= *fail {
			return exitFindings, nil
		}
	}
	return exitOK, nil
}

func summary(fs []audit.Finding) map[string]int {
	m := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

func writeAuditText(w io.Writer, fs []audit.Finding) error {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "[%s] %s %s  %s\n", strings.ToUpper(f.Severity.String()), f.RuleID, f.RuleName, f.Location)
		fmt.Fprintf(&b, "    %s\n", f.Message)
	}
	s := summary(fs)
	if len(fs) > 0 {
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%d findings: %d critical, %d high, %d medium, %d low, %d info\n",
		len(fs), s["critical"], s["high"], s["medium"], s["low"], s["info"])
	_, err := io.WriteString(w, b.String())
	return err
}

func cmdPaths(args []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("paths", stderr)
	var c common
	c.register(fs, "text|json|dot|mermaid")
	var from, groups stringList
	fs.Var(&from, "from", "source subject (repeatable; default: every non-system subject)")
	fs.Var(&groups, "group", "additional group membership applied to --from subjects (repeatable)")
	to := fs.String("to", "cluster-admin", `target: "cluster-admin" or a SUBJECT`)
	includeSystem := fs.Bool("include-system", false, "include system:* principals and kube-system service accounts as sources")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 0, err
	}
	if len(pos) != 0 {
		return 0, usagef("unexpected arguments: %s", strings.Join(pos, " "))
	}
	if err := checkFormat(c.output, "text", "json", "dot", "mermaid"); err != nil {
		return 0, err
	}
	var sources []rbac.Identity
	for _, f := range from {
		id, err := rbac.ParseIdentity(f)
		if err != nil {
			return 0, usagef("--from: %v", err)
		}
		id.ExtraGroups = groups
		sources = append(sources, id)
	}
	if len(groups) > 0 && len(sources) == 0 {
		return 0, usagef("--group requires --from")
	}
	target := paths.AdminNode
	if *to != "cluster-admin" && *to != "" {
		id, err := rbac.ParseIdentity(*to)
		if err != nil {
			return 0, usagef("--to: %v", err)
		}
		target = id.Key()
	}
	e, err := load(&c, stderr)
	if err != nil {
		return 0, err
	}
	g := paths.Build(e, paths.Options{Extra: sources})
	ps := g.Find(paths.FindOptions{From: sources, To: target, IncludeSystem: *includeSystem})
	switch c.output {
	case "json":
		type out struct {
			Target string       `json:"target"`
			Nodes  int          `json:"nodes"`
			Edges  int          `json:"edges"`
			Paths  []paths.Path `json:"paths"`
		}
		if ps == nil {
			ps = []paths.Path{}
		}
		return exitOK, report.JSON(stdout, out{Target: target, Nodes: len(g.Nodes), Edges: g.EdgeCount(), Paths: ps})
	case "dot":
		return exitOK, report.DOT(stdout, ps)
	case "mermaid":
		return exitOK, report.Mermaid(stdout, ps)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Escalation graph: %d nodes, %d edges. Target: %s\n\n", len(g.Nodes), g.EdgeCount(), target)
	if len(ps) == 0 {
		b.WriteString("No escalation paths found.\n")
	}
	for _, p := range ps {
		approxNote := ""
		if p.Approximate() {
			approxNote = "  [approximate]"
		}
		fmt.Fprintf(&b, "%s -> %s  (%d hop%s)%s\n", p.Source.String(), p.Target, len(p.Hops), plural(len(p.Hops)), approxNote)
		for i, h := range p.Hops {
			approx := ""
			if h.Approximate {
				approx = " (approximate)"
			}
			fmt.Fprintf(&b, "  %d. %s =[%s]=> %s%s\n", i+1, h.From, h.Technique, h.To, approx)
			fmt.Fprintf(&b, "     how: %s\n", h.Detail)
			for _, ev := range h.Evidence {
				fmt.Fprintf(&b, "     via: %s\n", ev)
			}
		}
		b.WriteString("\n")
	}
	if len(ps) > 0 {
		fmt.Fprintf(&b, "%d subject(s) can reach %s.\n", len(ps), target)
	}
	_, err = io.WriteString(stdout, b.String())
	return exitOK, err
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func cmdRules(args []string, stdout io.Writer) (int, error) {
	if len(args) > 0 && (args[0] == "-o=json" || (len(args) > 1 && args[0] == "-o" && args[1] == "json")) {
		return exitOK, report.JSON(stdout, audit.Rules)
	}
	t := &report.Table{Header: []string{"ID", "SEVERITY", "NAME", "TITLE"}}
	for _, r := range audit.Rules {
		t.Add(r.ID, r.Severity.String(), r.Name, r.Title)
	}
	if err := t.Write(stdout); err != nil {
		return 0, err
	}
	fmt.Fprintln(stdout, "\nSeverity shown is the default; actual severity depends on scope (cluster-wide vs namespace) and resourceNames restrictions.")
	return exitOK, nil
}
