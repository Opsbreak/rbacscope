package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

// Related is a secondary location attached to a finding.
type Related struct {
	Source  model.Source `json:"source"`
	Message string       `json:"message"`
}

// Finding is a single audit result.
type Finding struct {
	RuleID      string       `json:"ruleId"`
	RuleName    string       `json:"ruleName"`
	Severity    Severity     `json:"severity"`
	Message     string       `json:"message"`
	Subjects    []string     `json:"subjects,omitempty"`
	Scope       string       `json:"scope,omitempty"`
	Binding     string       `json:"binding,omitempty"`
	Role        string       `json:"role,omitempty"`
	Location    model.Source `json:"location"`
	Related     []Related    `json:"related,omitempty"`
	Fingerprint string       `json:"fingerprint"`
}

// Options control the audit.
type Options struct {
	// IncludeSystem also evaluates built-in bootstrap bindings (names starting
	// with "system:" or "kubeadm:", or labelled
	// kubernetes.io/bootstrapping=rbac-defaults). The cluster-admin inventory
	// (RS015) always includes them.
	IncludeSystem bool
}

// IsSystemBinding reports whether a binding is a Kubernetes/kubeadm
// bootstrap binding.
func IsSystemBinding(b *model.Binding) bool {
	return strings.HasPrefix(b.Meta.Name, "system:") || strings.HasPrefix(b.Meta.Name, "kubeadm:") ||
		b.Meta.Labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}

type auditor struct {
	e        *rbac.Engine
	opts     Options
	findings []Finding
	// adminSAs maps namespace -> cluster-admin-equivalent service accounts.
	adminSAs map[string][]string
}

// Run evaluates every rule and returns findings sorted by severity
// (highest first), rule ID and location.
func Run(e *rbac.Engine, opts Options) []Finding {
	a := &auditor{e: e, opts: opts, adminSAs: map[string][]string{}}
	for _, ns := range e.Namespaces() {
		for _, sa := range e.ServiceAccounts(ns) {
			id := rbac.SAID(ns, sa.Meta.Name)
			if e.IsClusterAdmin(id) {
				a.adminSAs[ns] = append(a.adminSAs[ns], id.String())
			}
		}
	}
	for _, b := range e.Bindings() {
		a.inventory(b)
		if IsSystemBinding(b) && !opts.IncludeSystem {
			continue
		}
		a.binding(b)
	}
	for _, b := range e.Dangling {
		if IsSystemBinding(b) && !opts.IncludeSystem {
			continue
		}
		a.add(Finding{
			RuleID: "RS016", Severity: Low, Binding: b.Ref(), Role: b.RoleRefString(),
			Subjects: subjectStrings(b), Scope: scopeOf(b), Location: b.Source,
			Message: fmt.Sprintf("%s references %s, which does not exist in the input; subjects %s would receive whatever a future role of that name grants",
				b.Ref(), b.RoleRefString(), strings.Join(subjectStrings(b), ", ")),
		})
	}
	a.defaultSA()
	a.adminPods()

	sort.SliceStable(a.findings, func(i, j int) bool {
		fi, fj := a.findings[i], a.findings[j]
		if fi.Severity != fj.Severity {
			return fi.Severity > fj.Severity
		}
		if fi.RuleID != fj.RuleID {
			return fi.RuleID < fj.RuleID
		}
		if fi.Location.File != fj.Location.File {
			return fi.Location.File < fj.Location.File
		}
		if fi.Location.Line != fj.Location.Line {
			return fi.Location.Line < fj.Location.Line
		}
		return fi.Message < fj.Message
	})
	return a.findings
}

func (a *auditor) add(f Finding) {
	r, _ := RuleByID(f.RuleID)
	f.RuleName = r.Name
	h := sha256.Sum256([]byte(f.RuleID + "|" + f.Binding + "|" + f.Role + "|" + f.Scope + "|" + strings.Join(f.Subjects, ",") + "|" + f.Message))
	f.Fingerprint = hex.EncodeToString(h[:8])
	a.findings = append(a.findings, f)
}

func subjectStrings(b *model.Binding) []string {
	out := make([]string, 0, len(b.Subjects))
	for _, s := range b.Subjects {
		out = append(out, rbac.IdentityFromSubject(s).String())
	}
	return out
}

func scopeOf(b *model.Binding) string {
	if b.Kind == model.KindClusterRoleBinding {
		return "cluster-wide"
	}
	return "ns/" + b.Meta.Namespace
}

func scopeText(b *model.Binding) string {
	if b.Kind == model.KindClusterRoleBinding {
		return "cluster-wide"
	}
	return "in namespace " + b.Meta.Namespace
}

// check evaluates whether a role, as bound by b, allows a request template.
type check struct {
	ok         bool
	restricted bool // only name-restricted rules match
	names      []string
	from       []string
}

func (a *auditor) can(b *model.Binding, role *model.Role, verb, group, resource, sub string) check {
	attrs := rbac.Attributes{Verb: verb, APIGroup: group, Resource: resource, Subresource: sub}
	var c check
	if b.Kind == model.KindRoleBinding && rbac.ClusterScopedRequest(attrs) {
		return c
	}
	for _, er := range a.e.Rules(role) {
		ok, restricted := rbac.RuleAllowsAnyName(attrs, &er.Rule)
		if !ok {
			continue
		}
		if er.From != role {
			c.from = appendUnique(c.from, er.From.Ref())
		}
		if !restricted {
			c.ok, c.restricted = true, false
			continue
		}
		if !c.ok {
			c.ok, c.restricted = true, true
		}
		c.names = append(c.names, er.Rule.ResourceNames...)
	}
	return c
}

// canAny ORs several verbs.
func (a *auditor) canAny(b *model.Binding, role *model.Role, verbs []string, group, resource, sub string) (check, []string) {
	var out check
	var matched []string
	for _, v := range verbs {
		c := a.can(b, role, v, group, resource, sub)
		if !c.ok {
			continue
		}
		matched = append(matched, v)
		if !out.ok || (out.restricted && !c.restricted) {
			out.ok, out.restricted = true, c.restricted
		}
		out.names = append(out.names, c.names...)
		for _, f := range c.from {
			out.from = appendUnique(out.from, f)
		}
	}
	if out.ok && !out.restricted {
		out.names = nil
	}
	return out, matched
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func (c check) suffix() string {
	var parts []string
	if c.restricted {
		parts = append(parts, "limited to resourceNames ["+strings.Join(dedupe(c.names), ", ")+"]")
	}
	if len(c.from) > 0 {
		parts = append(parts, "rule aggregated from "+strings.Join(c.from, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		out = appendUnique(out, s)
	}
	return out
}

func (a *auditor) base(id string, sev Severity, b *model.Binding, role *model.Role, msg string) Finding {
	return Finding{
		RuleID: id, Severity: sev, Binding: b.Ref(), Role: role.Ref(), Scope: scopeOf(b),
		Subjects: subjectStrings(b), Location: b.Source, Message: msg,
		Related: []Related{{Source: role.Source, Message: "role " + role.Ref()}},
	}
}

func (a *auditor) who(b *model.Binding) string {
	return strings.Join(subjectStrings(b), ", ")
}

func pick(clusterWide bool, cw, ns Severity) Severity {
	if clusterWide {
		return cw
	}
	return ns
}

func (a *auditor) inventory(b *model.Binding) {
	role := a.e.RoleFor(b)
	isCA := role.Kind == model.KindClusterRole && role.Meta.Name == "cluster-admin"
	if !isCA && !a.e.RoleIsFullWildcard(role) {
		return
	}
	what := role.Ref()
	if !isCA {
		what += " (equivalent to cluster-admin)"
	}
	f := a.base("RS015", Info, b, role, fmt.Sprintf("%s binds %s %s to %s", b.Ref(), what, scopeText(b), a.who(b)))
	a.add(f)
}

var workloadKinds = []struct{ group, resource string }{
	{"apps", "deployments"}, {"apps", "statefulsets"}, {"apps", "daemonsets"}, {"apps", "replicasets"},
	{"batch", "jobs"}, {"batch", "cronjobs"}, {"", "replicationcontrollers"},
}

func (a *auditor) binding(b *model.Binding) {
	role := a.e.RoleFor(b)
	cw := b.Kind == model.KindClusterRoleBinding
	who := a.who(b)
	scope := scopeText(b)
	a.broadGroups(b, role, scope)

	// RS001 full wildcard / RS002 partial wildcards.
	full := false
	var wild []string
	for _, er := range a.e.Rules(role) {
		r := er.Rule
		if rbac.IsFullWildcard(&r) {
			full = true
			continue
		}
		var parts []string
		if containsStr(r.Verbs, "*") {
			parts = append(parts, "verbs")
		}
		if len(r.Resources) > 0 && containsStr(r.Resources, "*") {
			parts = append(parts, "resources")
		}
		if len(r.Resources) > 0 && containsStr(r.APIGroups, "*") {
			parts = append(parts, "apiGroups")
		}
		if len(parts) > 0 {
			wild = append(wild, fmt.Sprintf("%s in %s", strings.Join(parts, "+"), ruleString(r)))
		}
	}
	if full {
		a.add(a.base("RS001", pick(cw, Critical, High), b, role,
			fmt.Sprintf("%s grants %s full wildcard access (verbs=* apiGroups=* resources=*) %s via %s", b.Ref(), who, scope, role.Ref())))
	}
	if len(wild) > 0 && !full {
		a.add(a.base("RS002", pick(cw, Medium, Low), b, role,
			fmt.Sprintf("%s grants %s wildcard rules %s via %s: %s", b.Ref(), who, scope, role.Ref(), strings.Join(dedupe(wild), "; "))))
	}
	if full {
		// Everything below is implied by the wildcard; RS001 already covers it.
		return
	}

	// RS003 escalate / bind.
	var eb []string
	var ebc check
	for _, res := range []string{"clusterroles", "roles"} {
		c, verbs := a.canAny(b, role, []string{"escalate", "bind"}, "rbac.authorization.k8s.io", res, "")
		if c.ok {
			eb = append(eb, strings.Join(verbs, "/")+" "+res)
			if !ebc.ok || (ebc.restricted && !c.restricted) {
				ebc = c
			}
		}
	}
	if len(eb) > 0 {
		sev := pick(cw, Critical, High)
		if ebc.restricted {
			sev = sev.Lower()
		}
		a.add(a.base("RS003", sev, b, role,
			fmt.Sprintf("%s can %s %s via %s%s", who, strings.Join(eb, ", "), scope, role.Ref(), ebc.suffix())))
	}

	// RS004 impersonation.
	var imp []string
	impSev := Info
	var impFrom []string
	for _, t := range []struct{ group, res, sub string }{
		{"", "users", ""}, {"", "groups", ""}, {"", "serviceaccounts", ""},
		{"authentication.k8s.io", "uids", ""}, {"authentication.k8s.io", "userextras", "*"},
	} {
		c := a.can(b, role, "impersonate", t.group, t.res, t.sub)
		if !c.ok {
			continue
		}
		sev := Critical
		if t.res == "serviceaccounts" {
			sev = pick(cw, Critical, High)
		} else if t.res == "uids" || t.res == "userextras" {
			sev = Medium
		}
		if c.restricted && !(t.res == "groups" && containsStr(c.names, rbac.GroupMasters)) {
			sev = sev.Lower()
		}
		if sev > impSev {
			impSev = sev
		}
		label := t.res
		if c.restricted {
			label += " [" + strings.Join(dedupe(c.names), ", ") + "]"
		}
		imp = append(imp, label)
		for _, f := range c.from {
			impFrom = appendUnique(impFrom, f)
		}
	}
	if len(imp) > 0 {
		a.add(a.base("RS004", impSev, b, role,
			fmt.Sprintf("%s can impersonate %s %s via %s%s", who, strings.Join(imp, ", "), scope, role.Ref(), check{from: impFrom}.suffix())))
	}

	// RS005 workload creation.
	var wl, wlVerbs []string
	var wlFrom []string
	if c := a.can(b, role, "create", "", "pods", ""); c.ok {
		wl = append(wl, "create pods")
		wlVerbs = append(wlVerbs, "pods-only")
		wlFrom = append(wlFrom, c.from...)
	}
	for _, w := range workloadKinds {
		c, verbs := a.canAny(b, role, []string{"create", "update", "patch"}, w.group, w.resource, "")
		if c.ok {
			// Group resources sharing the same verb set: "create/update/patch deployments, jobs".
			v := strings.Join(verbs, "/")
			if n := len(wl); n > 0 && wlVerbs[n-1] == v {
				wl[n-1] += ", " + w.resource
			} else {
				wl = append(wl, v+" "+w.resource)
				wlVerbs = append(wlVerbs, v)
			}
			wlFrom = append(wlFrom, c.from...)
		}
	}
	if len(wl) > 0 {
		sev := pick(cw, Critical, High)
		extra := ""
		if cw {
			extra = "; this allows running a pod as any service account in any namespace, including kube-system"
		} else if admins := a.adminSAs[b.Meta.Namespace]; len(admins) > 0 {
			sev = Critical
			extra = "; the namespace contains cluster-admin-equivalent service account(s) " + strings.Join(admins, ", ")
		} else if sas := a.e.ServiceAccounts(b.Meta.Namespace); len(sas) > 0 {
			var names []string
			for _, sa := range sas {
				names = append(names, sa.Meta.Name)
			}
			extra = "; reachable service accounts: " + strings.Join(names, ", ")
		}
		suffix := ""
		if len(wlFrom) > 0 {
			suffix = " (rule aggregated from " + strings.Join(dedupe(wlFrom), ", ") + ")"
		}
		a.add(a.base("RS005", sev, b, role,
			fmt.Sprintf("%s can %s %s via %s%s%s", who, strings.Join(wl, ", "), scope, role.Ref(), suffix, extra)))
	}

	// RS006 exec / attach.
	var ex []string
	var exc check
	for _, sub := range []string{"exec", "attach"} {
		c, verbs := a.canAny(b, role, []string{"create", "get"}, "", "pods", sub)
		if c.ok {
			ex = append(ex, strings.Join(verbs, "/")+" pods/"+sub)
			if !exc.ok || (exc.restricted && !c.restricted) {
				exc = c
			}
		}
	}
	if len(ex) > 0 {
		sev := pick(cw, Critical, High)
		if exc.restricted {
			sev = sev.Lower()
		}
		a.add(a.base("RS006", sev, b, role,
			fmt.Sprintf("%s can %s %s via %s%s", who, strings.Join(ex, ", "), scope, role.Ref(), exc.suffix())))
	}

	// RS007 nodes/proxy.
	if c, verbs := a.canAny(b, role, []string{"get", "create"}, "", "nodes", "proxy"); c.ok {
		sev := Critical
		if c.restricted {
			sev = High
		}
		a.add(a.base("RS007", sev, b, role,
			fmt.Sprintf("%s can %s nodes/proxy %s via %s%s", who, strings.Join(verbs, "/"), scope, role.Ref(), c.suffix())))
	}

	// RS008 secrets read.
	if c, verbs := a.canAny(b, role, []string{"get", "list", "watch"}, "", "secrets", ""); c.ok {
		sev := pick(cw, Critical, High)
		if c.restricted {
			sev = pick(cw, Medium, Low)
		}
		a.add(a.base("RS008", sev, b, role,
			fmt.Sprintf("%s can %s secrets %s via %s%s", who, strings.Join(verbs, "/"), scope, role.Ref(), c.suffix())))
	}

	// RS009 serviceaccounts/token.
	if c := a.can(b, role, "create", "", "serviceaccounts", "token"); c.ok {
		sev := pick(cw, Critical, High)
		if c.restricted {
			sev = sev.Lower()
		}
		a.add(a.base("RS009", sev, b, role,
			fmt.Sprintf("%s can create serviceaccounts/token %s via %s%s", who, scope, role.Ref(), c.suffix())))
	}

	// RS010 CSR create + approve.
	csrCreate := a.can(b, role, "create", "certificates.k8s.io", "certificatesigningrequests", "")
	csrApprove, _ := a.canAny(b, role, []string{"update", "patch"}, "certificates.k8s.io", "certificatesigningrequests", "approval")
	if csrCreate.ok && csrApprove.ok {
		signer := a.can(b, role, "approve", "certificates.k8s.io", "signers", "")
		signerOK := signer.ok && (!signer.restricted || containsStr(signer.names, "kubernetes.io/kube-apiserver-client") || containsStr(signer.names, "kubernetes.io/*"))
		sev := Critical
		note := "; also holds approve on the kube-apiserver-client signer, so it can mint client certificates for any identity including system:masters"
		if !signerOK {
			sev = Medium
			note = "; no approve permission on the kubernetes.io/kube-apiserver-client signer was found, which limits abuse to other signers"
		}
		a.add(a.base("RS010", sev, b, role,
			fmt.Sprintf("%s can create certificatesigningrequests and update certificatesigningrequests/approval %s via %s%s", who, scope, role.Ref(), note)))
	}

	// RS011 admission webhooks.
	for _, w := range []struct {
		res string
		sev Severity
	}{{"mutatingwebhookconfigurations", Critical}, {"validatingwebhookconfigurations", High}} {
		if c, verbs := a.canAny(b, role, []string{"create", "update", "patch"}, "admissionregistration.k8s.io", w.res, ""); c.ok {
			sev := w.sev
			if c.restricted {
				sev = sev.Lower()
			}
			a.add(a.base("RS011", sev, b, role,
				fmt.Sprintf("%s can %s %s %s via %s%s", who, strings.Join(verbs, "/"), w.res, scope, role.Ref(), c.suffix())))
		}
	}

	// RS012 persistentvolumes create.
	if c := a.can(b, role, "create", "", "persistentvolumes", ""); c.ok {
		a.add(a.base("RS012", High, b, role,
			fmt.Sprintf("%s can create persistentvolumes %s via %s; a hostPath PersistentVolume exposes node filesystems%s", who, scope, role.Ref(), c.suffix())))
	}

}

// broadGroups implements RS013.
func (a *auditor) broadGroups(b *model.Binding, role *model.Role, scope string) {
	if len(a.e.Rules(role)) > 0 {
		onlyNonResource := true
		for _, er := range a.e.Rules(role) {
			if len(er.Rule.Resources) > 0 {
				onlyNonResource = false
			}
		}
		for _, s := range b.Subjects {
			var sev Severity
			var who string
			switch {
			case s.Kind == model.SubjectGroup && s.Name == rbac.GroupUnauthenticated, s.Kind == model.SubjectUser && s.Name == "system:anonymous":
				sev, who = Critical, "unauthenticated (anonymous) requests"
			case s.Kind == model.SubjectGroup && s.Name == rbac.GroupAuthenticated:
				sev, who = High, "every authenticated identity, including every service account"
			case s.Kind == model.SubjectGroup && s.Name == rbac.GroupServiceAccounts:
				sev, who = Medium, "every service account in the cluster"
			default:
				continue
			}
			if onlyNonResource {
				sev = Low
			}
			f := a.base("RS013", sev, b, role,
				fmt.Sprintf("%s grants %s to %s %s", b.Ref(), role.Ref(), who, scope))
			f.Subjects = []string{rbac.IdentityFromSubject(s).String()}
			a.add(f)
		}
	}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func ruleString(r model.PolicyRule) string {
	if len(r.NonResourceURLs) > 0 && len(r.Resources) == 0 {
		return fmt.Sprintf("{verbs=%s urls=%s}", strings.Join(r.Verbs, ","), strings.Join(r.NonResourceURLs, ","))
	}
	return fmt.Sprintf("{verbs=%s apiGroups=%s resources=%s}", strings.Join(r.Verbs, ","), groupsString(r.APIGroups), strings.Join(r.Resources, ","))
}

func groupsString(gs []string) string {
	out := make([]string, len(gs))
	for i, g := range gs {
		if g == "" {
			g = `""`
		}
		out[i] = g
	}
	return strings.Join(out, ",")
}

// defaultSA implements RS014.
func (a *auditor) defaultSA() {
	for _, ns := range a.e.Namespaces() {
		id := rbac.SAID(ns, "default")
		var grants []rbac.Grant
		for _, g := range a.e.GrantsFor(id) {
			if IsSystemBinding(g.Binding) && !a.opts.IncludeSystem {
				continue
			}
			// Only bindings that name this service account directly; grants
			// through system:serviceaccounts / system:authenticated are
			// covered by RS013.
			sid := rbac.IdentityFromSubject(g.Subject)
			if sid.Kind != model.SubjectServiceAccount || sid.Namespace != ns || sid.Name != "default" {
				continue
			}
			if len(a.e.Rules(g.Role)) == 0 {
				continue
			}
			grants = append(grants, g)
		}
		if len(grants) == 0 {
			continue
		}
		var pods []*model.Pod
		for _, p := range a.e.Pods(ns) {
			if p.ServiceAccountName == "default" && a.e.AutomountEffective(p) {
				pods = append(pods, p)
			}
		}
		if len(pods) == 0 {
			continue
		}
		sev := Medium
		if a.e.IsClusterAdmin(id) {
			sev = Critical
		}
		var bnames, pnames []string
		var related []Related
		for _, g := range grants {
			bnames = append(bnames, g.Binding.Ref()+" -> "+g.Role.Ref())
			related = append(related, Related{Source: g.Binding.Source, Message: g.Binding.Ref()})
		}
		for _, p := range pods {
			pnames = append(pnames, p.Ref())
		}
		a.add(Finding{
			RuleID: "RS014", Severity: sev, Subjects: []string{id.String()}, Scope: "ns/" + ns,
			Location: pods[0].Source, Related: related,
			Message: fmt.Sprintf("%s has permissions (%s) and its token is automounted into %s",
				id.String(), strings.Join(bnames, ", "), strings.Join(pnames, ", ")),
		})
	}
}

// adminPods implements RS017.
func (a *auditor) adminPods() {
	for _, ns := range a.e.Namespaces() {
		for _, p := range a.e.Pods(ns) {
			if !a.e.AutomountEffective(p) {
				continue
			}
			id := rbac.SAID(ns, p.ServiceAccountName)
			if !a.e.IsClusterAdmin(id) {
				continue
			}
			extra := ""
			if p.Privileged || p.HostPath {
				extra = " The pod is also privileged or mounts hostPath volumes."
			}
			a.add(Finding{
				RuleID: "RS017", Severity: High, Subjects: []string{id.String()}, Scope: "ns/" + ns,
				Location: p.Source,
				Message:  fmt.Sprintf("%s runs as %s, which is cluster-admin-equivalent, with its token automounted.%s", p.Ref(), id.String(), extra),
			})
		}
	}
}

// Max returns the highest severity among findings (Info if none) and whether
// any finding exists.
func Max(fs []Finding) (Severity, bool) {
	m := Info
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m, len(fs) > 0
}

// Filter returns findings at or above min.
func Filter(fs []Finding, min Severity) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}
