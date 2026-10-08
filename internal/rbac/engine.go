package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/model"
)

// EffRule is a policy rule together with the role that literally defines it.
// For aggregated ClusterRoles, From is the aggregated (source) ClusterRole.
type EffRule struct {
	Rule model.PolicyRule
	From *model.Role
}

// Grant is one binding that applies to an identity.
type Grant struct {
	Binding *model.Binding
	Role    *model.Role
	// Subject is the binding subject through which the identity matched.
	Subject model.Subject
	// Namespace is "" for ClusterRoleBindings (cluster-wide) and the binding
	// namespace for RoleBindings.
	Namespace string
}

// ClusterWide reports whether the grant applies in all namespaces and to
// cluster-scoped resources.
func (g Grant) ClusterWide() bool { return g.Namespace == "" }

// Scope renders the grant scope.
func (g Grant) Scope() string {
	if g.Namespace == "" {
		return "cluster-wide"
	}
	return "ns/" + g.Namespace
}

// Engine is an indexed, aggregation-resolved view of a cluster's RBAC state.
type Engine struct {
	Cluster *model.Cluster

	clusterRoles map[string]*model.Role
	roles        map[string]*model.Role // ns/name
	effective    map[*model.Role][]EffRule
	aggregatedBy map[*model.Role][]*model.Role

	bindings  []*model.Binding // CRBs then RBs, deterministic order
	bySubject map[string][]*model.Binding
	roleOf    map[*model.Binding]*model.Role

	// Dangling are bindings whose referenced role does not exist.
	Dangling []*model.Binding

	sas         map[string]*model.ServiceAccount // ns/name
	saByNS      map[string][]*model.ServiceAccount
	podsByNS    map[string][]*model.Pod
	tokensByNS  map[string][]*model.Secret
	namespaces  []string
	nsSet       map[string]bool
	grantsCache map[string][]Grant
}

// NewEngine indexes a cluster, resolves ClusterRole aggregation and records
// dangling bindings.
func NewEngine(c *model.Cluster) *Engine {
	e := &Engine{
		Cluster:      c,
		clusterRoles: map[string]*model.Role{},
		roles:        map[string]*model.Role{},
		effective:    map[*model.Role][]EffRule{},
		aggregatedBy: map[*model.Role][]*model.Role{},
		bySubject:    map[string][]*model.Binding{},
		roleOf:       map[*model.Binding]*model.Role{},
		sas:          map[string]*model.ServiceAccount{},
		saByNS:       map[string][]*model.ServiceAccount{},
		podsByNS:     map[string][]*model.Pod{},
		tokensByNS:   map[string][]*model.Secret{},
		nsSet:        map[string]bool{},
		grantsCache:  map[string][]Grant{},
	}
	for _, r := range c.ClusterRoles {
		e.clusterRoles[r.Meta.Name] = r
	}
	for _, r := range c.Roles {
		e.roles[r.Meta.Namespace+"/"+r.Meta.Name] = r
		e.addNS(r.Meta.Namespace)
	}
	e.aggregate()

	crbs := append([]*model.Binding{}, c.ClusterRoleBindings...)
	sort.SliceStable(crbs, func(i, j int) bool { return crbs[i].Meta.Name < crbs[j].Meta.Name })
	rbs := append([]*model.Binding{}, c.RoleBindings...)
	sort.SliceStable(rbs, func(i, j int) bool {
		if rbs[i].Meta.Namespace != rbs[j].Meta.Namespace {
			return rbs[i].Meta.Namespace < rbs[j].Meta.Namespace
		}
		return rbs[i].Meta.Name < rbs[j].Meta.Name
	})
	for _, b := range append(crbs, rbs...) {
		if b.Kind == model.KindRoleBinding {
			e.addNS(b.Meta.Namespace)
		}
		role := e.resolveRoleRef(b)
		if role == nil {
			e.Dangling = append(e.Dangling, b)
			continue
		}
		e.roleOf[b] = role
		e.bindings = append(e.bindings, b)
		seen := map[string]bool{}
		for _, s := range b.Subjects {
			k := subjectKey(s)
			if seen[k] {
				continue
			}
			seen[k] = true
			e.bySubject[k] = append(e.bySubject[k], b)
			if s.Kind == model.SubjectServiceAccount && s.Namespace != "" {
				e.ensureSA(s.Namespace, s.Name)
			}
		}
	}

	for _, ns := range c.Namespaces {
		e.addNS(ns.Meta.Name)
	}
	for _, sa := range c.ServiceAccounts {
		key := sa.Meta.Namespace + "/" + sa.Meta.Name
		if old, ok := e.sas[key]; ok && old.Implicit {
			*old = *sa
			continue
		}
		e.sas[key] = sa
		e.saByNS[sa.Meta.Namespace] = append(e.saByNS[sa.Meta.Namespace], sa)
		e.addNS(sa.Meta.Namespace)
	}
	for _, p := range c.Pods {
		e.podsByNS[p.Meta.Namespace] = append(e.podsByNS[p.Meta.Namespace], p)
		e.addNS(p.Meta.Namespace)
		e.ensureSA(p.Meta.Namespace, p.ServiceAccountName)
	}
	for _, s := range c.Secrets {
		if s.Type != model.SecretTypeSAToken {
			continue
		}
		e.tokensByNS[s.Meta.Namespace] = append(e.tokensByNS[s.Meta.Namespace], s)
		e.addNS(s.Meta.Namespace)
	}
	// Every namespace has a "default" service account.
	for ns := range e.nsSet {
		e.ensureSA(ns, "default")
	}
	for ns := range e.nsSet {
		e.namespaces = append(e.namespaces, ns)
	}
	sort.Strings(e.namespaces)
	for ns := range e.saByNS {
		list := e.saByNS[ns]
		sort.Slice(list, func(i, j int) bool { return list[i].Meta.Name < list[j].Meta.Name })
	}
	return e
}

func (e *Engine) addNS(ns string) {
	if ns != "" {
		e.nsSet[ns] = true
	}
}

func (e *Engine) ensureSA(ns, name string) *model.ServiceAccount {
	key := ns + "/" + name
	if sa, ok := e.sas[key]; ok {
		return sa
	}
	sa := &model.ServiceAccount{Meta: model.ObjectMeta{Namespace: ns, Name: name}, Implicit: true}
	e.sas[key] = sa
	e.saByNS[ns] = append(e.saByNS[ns], sa)
	e.addNS(ns)
	return sa
}

func (e *Engine) resolveRoleRef(b *model.Binding) *model.Role {
	switch b.RoleRef.Kind {
	case model.KindClusterRole:
		return e.clusterRoles[b.RoleRef.Name]
	case model.KindRole:
		if b.Kind != model.KindRoleBinding {
			return nil
		}
		return e.roles[b.Meta.Namespace+"/"+b.RoleRef.Name]
	}
	return nil
}

func ruleKey(r *model.PolicyRule) string {
	return strings.Join([]string{
		strings.Join(r.Verbs, ","), strings.Join(r.APIGroups, ","), strings.Join(r.Resources, ","),
		strings.Join(r.ResourceNames, ","), strings.Join(r.NonResourceURLs, ","),
	}, "|")
}

// aggregate resolves aggregationRule on ClusterRoles to a fixpoint. The
// effective rules of an aggregating ClusterRole are the union of its exported
// rules (which the aggregation controller keeps in sync on a live cluster)
// and the rules of every ClusterRole matched by any of its selectors.
// Nested aggregation (admin <- edit <- view) is resolved iteratively.
func (e *Engine) aggregate() {
	for _, r := range e.Cluster.Roles {
		e.effective[r] = ownRules(r)
	}
	names := make([]string, 0, len(e.clusterRoles))
	for n := range e.clusterRoles {
		names = append(names, n)
	}
	sort.Strings(names)
	keys := map[*model.Role]map[string]int{}
	for _, n := range names {
		r := e.clusterRoles[n]
		e.effective[r] = ownRules(r)
		keys[r] = map[string]int{}
		for i := range e.effective[r] {
			keys[r][ruleKey(&e.effective[r][i].Rule)] = i
		}
	}
	for iter := 0; iter <= len(names); iter++ {
		changed := false
		for _, an := range names {
			agg := e.clusterRoles[an]
			if agg.AggregationRule == nil {
				continue
			}
			for _, sn := range names {
				src := e.clusterRoles[sn]
				if src == agg || !e.selectedBy(agg, src) {
					continue
				}
				if iter == 0 {
					e.aggregatedBy[agg] = append(e.aggregatedBy[agg], src)
				}
				for _, er := range e.effective[src] {
					k := ruleKey(&er.Rule)
					if idx, ok := keys[agg][k]; ok {
						// Prefer attributing the rule to the role that defines it.
						if e.effective[agg][idx].From == agg && er.From != agg {
							e.effective[agg][idx].From = er.From
						}
						continue
					}
					keys[agg][k] = len(e.effective[agg])
					e.effective[agg] = append(e.effective[agg], er)
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
}

func ownRules(r *model.Role) []EffRule {
	out := make([]EffRule, 0, len(r.Rules))
	seen := map[string]bool{}
	for _, rule := range r.Rules {
		k := ruleKey(&rule)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, EffRule{Rule: rule, From: r})
	}
	return out
}

func (e *Engine) selectedBy(agg, src *model.Role) bool {
	for _, sel := range agg.AggregationRule.ClusterRoleSelectors {
		if SelectorMatches(sel, src.Meta.Labels) {
			return true
		}
	}
	return false
}

// Rules returns the effective (aggregation-resolved) rules of a role.
func (e *Engine) Rules(r *model.Role) []EffRule { return e.effective[r] }

// AggregatedFrom returns the ClusterRoles an aggregating ClusterRole selects.
func (e *Engine) AggregatedFrom(r *model.Role) []*model.Role { return e.aggregatedBy[r] }

// ClusterRole looks up a ClusterRole by name.
func (e *Engine) ClusterRole(name string) *model.Role { return e.clusterRoles[name] }

// RoleFor returns the role a (non-dangling) binding references.
func (e *Engine) RoleFor(b *model.Binding) *model.Role { return e.roleOf[b] }

// Bindings returns all non-dangling bindings (ClusterRoleBindings first).
func (e *Engine) Bindings() []*model.Binding { return e.bindings }

// Namespaces returns every namespace seen in the input, sorted.
func (e *Engine) Namespaces() []string { return e.namespaces }

// ServiceAccounts returns the service accounts in a namespace (including
// implicit ones such as "default"), sorted by name.
func (e *Engine) ServiceAccounts(ns string) []*model.ServiceAccount { return e.saByNS[ns] }

// ServiceAccount looks up a service account.
func (e *Engine) ServiceAccount(ns, name string) *model.ServiceAccount { return e.sas[ns+"/"+name] }

// Pods returns pods and workload pod templates in a namespace.
func (e *Engine) Pods(ns string) []*model.Pod { return e.podsByNS[ns] }

// TokenSecrets returns service-account-token secrets in a namespace.
func (e *Engine) TokenSecrets(ns string) []*model.Secret { return e.tokensByNS[ns] }

// AutomountEffective reports whether a pod gets an API token mounted: the
// pod setting wins, then the service account setting, default true.
func (e *Engine) AutomountEffective(p *model.Pod) bool {
	if p.AutomountServiceAccountToken != nil {
		return *p.AutomountServiceAccountToken
	}
	if sa := e.ServiceAccount(p.Meta.Namespace, p.ServiceAccountName); sa != nil && sa.AutomountServiceAccountToken != nil {
		return *sa.AutomountServiceAccountToken
	}
	return true
}

// GrantsFor returns every binding that applies to an identity, in
// deterministic order (ClusterRoleBindings first).
func (e *Engine) GrantsFor(id Identity) []Grant {
	ck := id.Key() + "|" + strings.Join(id.ExtraGroups, ",")
	if g, ok := e.grantsCache[ck]; ok {
		return g
	}
	matched := map[*model.Binding]model.Subject{}
	for _, k := range id.subjectKeys() {
		for _, b := range e.bySubject[k] {
			if _, ok := matched[b]; ok {
				continue
			}
			for _, s := range b.Subjects {
				if subjectKey(s) == k {
					matched[b] = s
					break
				}
			}
		}
	}
	var out []Grant
	for _, b := range e.bindings {
		s, ok := matched[b]
		if !ok {
			continue
		}
		g := Grant{Binding: b, Role: e.roleOf[b], Subject: s}
		if b.Kind == model.KindRoleBinding {
			g.Namespace = b.Meta.Namespace
		}
		out = append(out, g)
	}
	e.grantsCache[ck] = out
	return out
}

// Match is one (grant, rule) pair that authorizes a request.
type Match struct {
	Grant      Grant
	Rule       EffRule
	Restricted bool // the rule only covers specific resourceNames
}

// grantApplies reports whether a grant is consulted for a request in ns
// (mirrors VisitRulesFor: ClusterRoleBindings always, RoleBindings only for
// requests in their namespace).
func grantApplies(g Grant, ns string) bool {
	return g.ClusterWide() || (ns != "" && g.Namespace == ns)
}

// Authorize evaluates a request exactly as the RBAC authorizer would and
// returns every matching (binding, rule). The request is allowed iff the
// result is non-empty, or the identity is a member of system:masters.
func (e *Engine) Authorize(id Identity, a Attributes) []Match {
	var out []Match
	for _, g := range e.GrantsFor(id) {
		if !grantApplies(g, a.Namespace) {
			continue
		}
		for _, r := range e.effective[g.Role] {
			if RuleAllows(a, &r.Rule) {
				out = append(out, Match{Grant: g, Rule: r})
			}
		}
	}
	return out
}

// Allowed is a boolean convenience wrapper around Authorize that also
// honours the system:masters superuser group.
func (e *Engine) Allowed(id Identity, a Attributes) bool {
	if contains(id.Groups(), GroupMasters) {
		return true
	}
	return len(e.Authorize(id, a)) > 0
}

// Access summarises where an identity can perform an action, ignoring
// resourceNames restrictions but recording them.
type Access struct {
	// ClusterWide: allowed for any object name via a ClusterRoleBinding.
	ClusterWide bool
	// ClusterNames: object names allowed via name-restricted cluster-wide rules.
	ClusterNames []string
	// NS maps namespace -> access granted by RoleBindings in that namespace.
	NS map[string]*NSAccess
	// Matches lists the evidence.
	Matches []Match
}

// NSAccess is the namespaced part of an Access.
type NSAccess struct {
	Any   bool
	Names []string
}

// Any reports whether any access exists.
func (a *Access) Any() bool {
	return a.ClusterWide || len(a.ClusterNames) > 0 || len(a.NS) > 0
}

// InNamespace reports whether the action is allowed for any name in ns.
func (a *Access) InNamespace(ns string) bool {
	if a.ClusterWide {
		return true
	}
	n, ok := a.NS[ns]
	return ok && n.Any
}

// NamesIn returns the explicitly allowed names in ns (for name-restricted
// grants), including cluster-wide name-restricted grants.
func (a *Access) NamesIn(ns string) []string {
	names := append([]string{}, a.ClusterNames...)
	if n, ok := a.NS[ns]; ok {
		names = append(names, n.Names...)
	}
	return names
}

// AllowsName reports whether a specific object in ns is covered.
func (a *Access) AllowsName(ns, name string) bool {
	return a.InNamespace(ns) || contains(a.NamesIn(ns), name)
}

// AccessFor computes an Access for an identity and request template
// (a.Namespace and a.Name are ignored). For cluster-scoped resources only
// ClusterRoleBindings count.
func (e *Engine) AccessFor(id Identity, a Attributes) *Access {
	return e.AccessForGrants(e.GrantsFor(id), contains(id.Groups(), GroupMasters), a)
}

// AccessForGrants is AccessFor over a precomputed grant list.
func (e *Engine) AccessForGrants(grants []Grant, superuser bool, a Attributes) *Access {
	acc := &Access{NS: map[string]*NSAccess{}}
	if superuser {
		acc.ClusterWide = true
	}
	clusterScopedReq := ClusterScopedRequest(a)
	for _, g := range grants {
		if !g.ClusterWide() && clusterScopedReq {
			continue
		}
		for _, r := range e.effective[g.Role] {
			ok, restricted := RuleAllowsAnyName(a, &r.Rule)
			if !ok {
				continue
			}
			acc.Matches = append(acc.Matches, Match{Grant: g, Rule: r, Restricted: restricted})
			if g.ClusterWide() {
				if restricted {
					acc.ClusterNames = append(acc.ClusterNames, r.Rule.ResourceNames...)
				} else {
					acc.ClusterWide = true
				}
				continue
			}
			n := acc.NS[g.Namespace]
			if n == nil {
				n = &NSAccess{}
				acc.NS[g.Namespace] = n
			}
			if restricted {
				n.Names = append(n.Names, r.Rule.ResourceNames...)
			} else {
				n.Any = true
			}
		}
	}
	return acc
}

// IsClusterAdmin reports whether the identity is cluster-admin-equivalent:
// it holds verbs=* apiGroups=* resources=* (no resourceNames) through a
// ClusterRoleBinding, or is a member of system:masters.
func (e *Engine) IsClusterAdmin(id Identity) bool {
	if contains(id.Groups(), GroupMasters) {
		return true
	}
	for _, g := range e.GrantsFor(id) {
		if !g.ClusterWide() {
			continue
		}
		for _, r := range e.effective[g.Role] {
			if IsFullWildcard(&r.Rule) {
				return true
			}
		}
	}
	return false
}

// RoleIsFullWildcard reports whether a role contains a */*/* rule.
func (e *Engine) RoleIsFullWildcard(r *model.Role) bool {
	for _, er := range e.effective[r] {
		if IsFullWildcard(&er.Rule) {
			return true
		}
	}
	return false
}

// Subjects returns every distinct identity named in a binding subject plus
// every known service account, sorted.
func (e *Engine) Subjects() []Identity {
	seen := map[string]Identity{}
	for _, b := range e.Cluster.ClusterRoleBindings {
		for _, s := range b.Subjects {
			id := IdentityFromSubject(s)
			if id.Kind == model.SubjectServiceAccount && id.Namespace == "" {
				continue
			}
			seen[id.Key()] = id
		}
	}
	for _, b := range e.Cluster.RoleBindings {
		for _, s := range b.Subjects {
			id := IdentityFromSubject(s)
			seen[id.Key()] = id
		}
	}
	for _, sa := range e.sas {
		id := SAID(sa.Meta.Namespace, sa.Meta.Name)
		seen[id.Key()] = id
	}
	out := make([]Identity, 0, len(seen))
	for _, id := range seen {
		out = append(out, id)
	}
	SortIdentities(out)
	return out
}

// SortIdentities sorts identities by kind (User, Group, ServiceAccount) then name.
func SortIdentities(ids []Identity) {
	rank := map[string]int{model.SubjectUser: 0, model.SubjectGroup: 1, model.SubjectServiceAccount: 2}
	sort.Slice(ids, func(i, j int) bool {
		if rank[ids[i].Kind] != rank[ids[j].Kind] {
			return rank[ids[i].Kind] < rank[ids[j].Kind]
		}
		return ids[i].String() < ids[j].String()
	})
}

// WhoCanRow is one result row of a who-can query.
type WhoCanRow struct {
	Subject    model.Subject    `json:"subject"`
	Scope      string           `json:"scope"`
	Binding    string           `json:"binding"`
	BindingSrc model.Source     `json:"bindingSource"`
	Role       string           `json:"role"`
	RuleFrom   string           `json:"ruleFrom,omitempty"`
	Names      []string         `json:"resourceNames,omitempty"`
	Rule       model.PolicyRule `json:"rule"`
}

// WhoCanQuery describes a who-can request.
type WhoCanQuery struct {
	Attributes
	// AllNamespaces evaluates RoleBindings in every namespace (used when no
	// namespace was given for a namespaced resource).
	AllNamespaces bool
}

// WhoCan returns every (subject, binding) that authorizes the request,
// together with the binding -> role -> rule chain. When the query has no
// object name, rules restricted by resourceNames are included and their
// names reported (except for create/deletecollection, which resourceNames
// can never authorize).
func (e *Engine) WhoCan(q WhoCanQuery) []WhoCanRow {
	a := q.Attributes
	clusterScopedReq := ClusterScopedRequest(a)
	var rows []WhoCanRow
	for _, b := range e.bindings {
		if b.Kind == model.KindRoleBinding {
			if clusterScopedReq {
				continue
			}
			if !q.AllNamespaces && b.Meta.Namespace != a.Namespace {
				continue
			}
		}
		role := e.roleOf[b]
		for _, r := range e.effective[role] {
			var ok, restricted bool
			if a.Name == "" {
				ok, restricted = RuleAllowsAnyName(a, &r.Rule)
			} else {
				ok = RuleAllows(a, &r.Rule)
			}
			if !ok {
				continue
			}
			scope := "cluster-wide"
			if b.Kind == model.KindRoleBinding {
				scope = "ns/" + b.Meta.Namespace
			}
			from := ""
			if r.From != role {
				from = r.From.Ref()
			}
			for _, s := range b.Subjects {
				row := WhoCanRow{Subject: s, Scope: scope, Binding: b.Ref(), BindingSrc: b.Source, Role: role.Ref(), RuleFrom: from, Rule: r.Rule}
				if restricted {
					row.Names = r.Rule.ResourceNames
				}
				rows = append(rows, row)
			}
		}
	}
	return dedupeRows(rows)
}

func dedupeRows(rows []WhoCanRow) []WhoCanRow {
	seen := map[string]int{}
	var out []WhoCanRow
	for _, r := range rows {
		k := fmt.Sprintf("%s|%s|%s|%s|%s", subjectKey(r.Subject), r.Scope, r.Binding, r.RuleFrom, strings.Join(r.Names, ","))
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = len(out)
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ki, kj := subjectSortKey(out[i].Subject), subjectSortKey(out[j].Subject)
		if ki != kj {
			return ki < kj
		}
		if out[i].Scope != out[j].Scope {
			return out[i].Scope < out[j].Scope
		}
		return out[i].Binding < out[j].Binding
	})
	return out
}

func subjectSortKey(s model.Subject) string {
	rank := map[string]string{model.SubjectUser: "0", model.SubjectGroup: "1", model.SubjectServiceAccount: "2"}[s.Kind]
	if rank == "" {
		rank = "3"
	}
	return rank + s.Namespace + "/" + s.Name
}

// PermissionRow is one entry of an identity's effective permission table.
type PermissionRow struct {
	Scope    string           `json:"scope"`
	Rule     model.PolicyRule `json:"rule"`
	Binding  string           `json:"binding"`
	Role     string           `json:"role"`
	RuleFrom string           `json:"ruleFrom,omitempty"`
	Via      string           `json:"via"`
}

// Permissions lists every rule granted to an identity.
func (e *Engine) Permissions(id Identity) []PermissionRow {
	var out []PermissionRow
	for _, g := range e.GrantsFor(id) {
		for _, r := range e.effective[g.Role] {
			from := ""
			if r.From != g.Role {
				from = r.From.Ref()
			}
			out = append(out, PermissionRow{
				Scope: g.Scope(), Rule: r.Rule, Binding: g.Binding.Ref(), Role: g.Role.Ref(),
				RuleFrom: from, Via: IdentityFromSubject(g.Subject).String(),
			})
		}
	}
	return out
}
