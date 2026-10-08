// Package paths builds a privilege-escalation graph over RBAC subjects and
// finds shortest escalation paths with breadth-first search.
//
// Nodes are identities (users, groups, service accounts) plus a synthetic
// "cluster-admin" node. An edge A -> B means "A can obtain B's permissions"
// using a concrete Kubernetes technique.
package paths

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/model"
	"github.com/Opsbreak/rbacscope/internal/rbac"
)

// Technique identifies how an edge is exploited.
type Technique string

// Techniques.
const (
	TechClusterAdmin   Technique = "holds-cluster-admin"
	TechCreatePod      Technique = "create-pod"
	TechModifyWorkload Technique = "modify-workload"
	TechTokenRequest   Technique = "create-token"
	TechImpersonate    Technique = "impersonate"
	TechBindRole       Technique = "bind-role"
	TechEscalateRole   Technique = "escalate-role"
	TechReadSecret     Technique = "read-token-secret"
	TechExecPod        Technique = "exec-into-pod"
	TechNodeProxy      Technique = "kubelet-nodes-proxy"
	TechCSR            Technique = "csr-mint-cert"
)

// TechniqueDescriptions explains every technique (used in docs and output).
var TechniqueDescriptions = map[Technique]string{
	TechClusterAdmin:   "Already holds verbs=* apiGroups=* resources=* through a ClusterRoleBinding (or is in system:masters).",
	TechCreatePod:      "Create a pod with spec.serviceAccountName set to the target SA; the SA token is mounted into the pod (automountServiceAccountToken: true can be set on the pod regardless of the SA default).",
	TechModifyWorkload: "Create or patch a Deployment/DaemonSet/StatefulSet/Job/CronJob/ReplicaSet so its pod template runs as the target SA; the controller creates the pod.",
	TechTokenRequest:   "Call the TokenRequest API (create serviceaccounts/token) to mint a token for the target SA.",
	TechImpersonate:    "Send requests with Impersonate-User / Impersonate-Group headers to act as the target.",
	TechBindRole:       "Use the bind verb to create a (Cluster)RoleBinding to a more powerful role (e.g. cluster-admin) for oneself.",
	TechEscalateRole:   "Use the escalate verb to add arbitrary rules to a role bound to oneself.",
	TechReadSecret:     "Read a kubernetes.io/service-account-token Secret, which contains a long-lived token for the target SA.",
	TechExecPod:        "Exec into an existing pod that runs as the target SA with an automounted token, and read the token.",
	TechNodeProxy:      "Use nodes/proxy to reach the kubelet API and run commands in pods on the node (approximation: pod placement is not known offline).",
	TechCSR:            "Create and approve a CertificateSigningRequest for the kube-apiserver-client signer with O=system:masters.",
}

// AdminNode is the key of the synthetic cluster-admin target.
const AdminNode = "cluster-admin"

// Edge is a single escalation step.
type Edge struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	Technique   Technique `json:"technique"`
	Detail      string    `json:"detail"`
	Evidence    []string  `json:"evidence,omitempty"`
	Approximate bool      `json:"approximate,omitempty"`
}

// Graph is the escalation graph.
type Graph struct {
	e     *rbac.Engine
	Nodes map[string]rbac.Identity
	Out   map[string][]Edge
	order []string

	adminRoles  []*model.Role // ClusterRoles equivalent to cluster-admin
	podCreators []*model.Role // ClusterRoles that can create pods (admin roles first)
}

// Options configure graph construction.
type Options struct {
	// Extra identities to add as nodes (e.g. --from with --group).
	Extra []rbac.Identity
}

// techniquePriority orders edges between the same pair of nodes; the first
// technique found is kept.
var techniquePriority = map[Technique]int{
	TechClusterAdmin: 0, TechImpersonate: 1, TechTokenRequest: 2, TechCreatePod: 3, TechBindRole: 4,
	TechEscalateRole: 5, TechReadSecret: 6, TechExecPod: 7, TechModifyWorkload: 8, TechCSR: 9, TechNodeProxy: 10,
}

// Build constructs the escalation graph for every subject in the cluster.
func Build(e *rbac.Engine, opts Options) *Graph {
	g := &Graph{e: e, Nodes: map[string]rbac.Identity{}, Out: map[string][]Edge{}}
	for _, id := range e.Subjects() {
		g.addNode(id)
	}
	g.addNode(rbac.GroupID(rbac.GroupMasters))
	crs := append([]*model.Role{}, e.Cluster.ClusterRoles...)
	sort.Slice(crs, func(i, j int) bool { return crs[i].Meta.Name < crs[j].Meta.Name })
	var others []*model.Role
	for _, cr := range crs {
		switch {
		case cr.Meta.Name == "cluster-admin" || e.RoleIsFullWildcard(cr):
			g.adminRoles = append(g.adminRoles, cr)
		case g.canCreatePods(cr):
			others = append(others, cr)
		}
	}
	g.podCreators = append(append([]*model.Role{}, g.adminRoles...), others...)
	for _, id := range opts.Extra {
		g.addNode(id)
	}
	// Snapshot node list: edges may introduce new (impersonation) nodes.
	keys := g.sortedKeys()
	for _, k := range keys {
		g.edgesFor(g.Nodes[k])
	}
	for k := range g.Out {
		edges := g.Out[k]
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].To != edges[j].To {
				return edges[i].To < edges[j].To
			}
			return techniquePriority[edges[i].Technique] < techniquePriority[edges[j].Technique]
		})
		// Keep the best technique per target.
		var out []Edge
		for _, ed := range edges {
			if len(out) > 0 && out[len(out)-1].To == ed.To {
				continue
			}
			out = append(out, ed)
		}
		g.Out[k] = out
	}
	return g
}

func (g *Graph) addNode(id rbac.Identity) string {
	k := id.Key()
	if old, ok := g.Nodes[k]; ok {
		if len(id.ExtraGroups) > 0 && len(old.ExtraGroups) == 0 {
			g.Nodes[k] = id
		}
		return k
	}
	g.Nodes[k] = id
	g.order = append(g.order, k)
	return k
}

func (g *Graph) sortedKeys() []string {
	keys := make([]string, 0, len(g.Nodes))
	for k := range g.Nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (g *Graph) addEdge(ed Edge) {
	if ed.From == ed.To {
		return
	}
	// Merged accesses can repeat the same binding; keep evidence unique.
	var ev []string
	seen := map[string]bool{}
	for _, x := range ed.Evidence {
		if !seen[x] {
			seen[x] = true
			ev = append(ev, x)
		}
	}
	ed.Evidence = ev
	g.Out[ed.From] = append(g.Out[ed.From], ed)
}

func evidence(acc *rbac.Access, ns string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range acc.Matches {
		if !m.Grant.ClusterWide() && ns != "" && m.Grant.Namespace != ns {
			continue
		}
		s := m.Grant.Binding.Ref() + " -> " + m.Grant.Role.Ref()
		if m.Rule.From != m.Grant.Role {
			s += " (rule from " + m.Rule.From.Ref() + ")"
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func mergeAccess(accs ...*rbac.Access) *rbac.Access {
	out := &rbac.Access{NS: map[string]*rbac.NSAccess{}}
	for _, a := range accs {
		out.ClusterWide = out.ClusterWide || a.ClusterWide
		out.ClusterNames = append(out.ClusterNames, a.ClusterNames...)
		out.Matches = append(out.Matches, a.Matches...)
		for ns, n := range a.NS {
			o := out.NS[ns]
			if o == nil {
				o = &rbac.NSAccess{}
				out.NS[ns] = o
			}
			o.Any = o.Any || n.Any
			o.Names = append(o.Names, n.Names...)
		}
	}
	return out
}

var workloads = []struct{ group, resource string }{
	{"apps", "deployments"}, {"apps", "daemonsets"}, {"apps", "statefulsets"}, {"apps", "replicasets"},
	{"batch", "jobs"}, {"batch", "cronjobs"}, {"", "replicationcontrollers"},
}

func (g *Graph) edgesFor(id rbac.Identity) {
	e := g.e
	from := id.Key()
	grants := e.GrantsFor(id)
	super := false
	for _, gr := range id.Groups() {
		if gr == rbac.GroupMasters {
			super = true
		}
	}
	acc := func(verb, group, res, sub string) *rbac.Access {
		return e.AccessForGrants(grants, super, rbac.Attributes{Verb: verb, APIGroup: group, Resource: res, Subresource: sub})
	}
	if e.IsClusterAdmin(id) {
		detail := "holds verbs=* apiGroups=* resources=* cluster-wide"
		var ev []string
		if super {
			detail = "member of system:masters (bypasses RBAC)"
		} else {
			for _, gr := range grants {
				if gr.ClusterWide() && e.RoleIsFullWildcard(gr.Role) {
					ev = append(ev, gr.Binding.Ref()+" -> "+gr.Role.Ref())
				}
			}
		}
		g.addEdge(Edge{From: from, To: AdminNode, Technique: TechClusterAdmin, Detail: detail, Evidence: ev})
		// Still compute other edges: they may matter for --to <identity>.
	}
	if len(grants) == 0 && !super {
		return
	}
	nss := e.Namespaces()
	saEdge := func(ns, name string, t Technique, detail string, ev []string, approx bool) {
		to := rbac.SAID(ns, name)
		g.addNode(to)
		g.addEdge(Edge{From: from, To: to.Key(), Technique: t, Detail: detail, Evidence: ev, Approximate: approx})
	}

	// create pods -> any SA in the namespace.
	createPods := acc("create", "", "pods", "")
	for _, ns := range nss {
		if !createPods.InNamespace(ns) {
			continue
		}
		ev := evidence(createPods, ns)
		for _, sa := range e.ServiceAccounts(ns) {
			saEdge(ns, sa.Meta.Name, TechCreatePod,
				fmt.Sprintf("create a pod in namespace %s with serviceAccountName: %s", ns, sa.Meta.Name), ev, false)
		}
	}

	// create/update/patch workload controllers -> any SA in the namespace.
	// Skipped where create-pod already applies (it would win anyway).
	for _, w := range workloads {
		create := acc("create", w.group, w.resource, "")
		upd := mergeAccess(acc("update", w.group, w.resource, ""), acc("patch", w.group, w.resource, ""))
		if !create.Any() && !upd.Any() {
			continue
		}
		for _, ns := range nss {
			if createPods.InNamespace(ns) {
				continue
			}
			var how string
			var ev []string
			if create.InNamespace(ns) {
				how = "create a " + strings.TrimSuffix(w.resource, "s")
				ev = evidence(create, ns)
			} else if upd.InNamespace(ns) || len(upd.NamesIn(ns)) > 0 {
				// update/patch: an existing workload must be modifiable.
				for _, p := range e.Pods(ns) {
					if p.OwnerKind != "" && strings.EqualFold(p.OwnerKind+"s", w.resource) && upd.AllowsName(ns, p.OwnerName) {
						how = "patch " + p.Ref() + " to change its pod template"
						ev = evidence(upd, ns)
						break
					}
				}
			}
			if how == "" {
				continue
			}
			for _, sa := range e.ServiceAccounts(ns) {
				saEdge(ns, sa.Meta.Name, TechModifyWorkload,
					fmt.Sprintf("%s in namespace %s with serviceAccountName: %s", how, ns, sa.Meta.Name), ev, false)
			}
		}
	}

	// TokenRequest.
	tok := acc("create", "", "serviceaccounts", "token")
	if tok.Any() {
		for _, ns := range nss {
			for _, sa := range e.ServiceAccounts(ns) {
				if tok.AllowsName(ns, sa.Meta.Name) {
					saEdge(ns, sa.Meta.Name, TechTokenRequest,
						fmt.Sprintf("create serviceaccounts/token for %s/%s (TokenRequest API)", ns, sa.Meta.Name), evidence(tok, ns), false)
				}
			}
		}
	}

	// Impersonation.
	impUsers := acc("impersonate", "", "users", "")
	if impUsers.Any() {
		for _, k := range g.sortedKeys() {
			n := g.Nodes[k]
			if n.Kind != model.SubjectUser {
				continue
			}
			if impUsers.ClusterWide || contains(impUsers.ClusterNames, n.Name) {
				g.addEdge(Edge{From: from, To: k, Technique: TechImpersonate,
					Detail: "impersonate user " + n.Name + " (Impersonate-User header)", Evidence: evidence(impUsers, "")})
			}
		}
		for _, name := range impUsers.ClusterNames {
			to := g.addNode(rbac.UserID(name))
			if g.Nodes[to].Kind == model.SubjectServiceAccount {
				// "system:serviceaccount:ns:name" usernames are SA identities.
				g.addEdge(Edge{From: from, To: to, Technique: TechImpersonate,
					Detail: "impersonate user " + name, Evidence: evidence(impUsers, "")})
				continue
			}
			g.addEdge(Edge{From: from, To: to, Technique: TechImpersonate,
				Detail: "impersonate user " + name + " (Impersonate-User header)", Evidence: evidence(impUsers, "")})
		}
		if impUsers.ClusterWide {
			// Impersonating a service account's username is equivalent to impersonating the SA.
			for _, ns := range nss {
				for _, sa := range e.ServiceAccounts(ns) {
					saEdge(ns, sa.Meta.Name, TechImpersonate,
						fmt.Sprintf("impersonate user system:serviceaccount:%s:%s", ns, sa.Meta.Name), evidence(impUsers, ""), false)
				}
			}
		}
		// Group impersonation requires user impersonation as well.
		impGroups := acc("impersonate", "", "groups", "")
		if impGroups.Any() {
			for _, k := range g.sortedKeys() {
				n := g.Nodes[k]
				if n.Kind != model.SubjectGroup {
					continue
				}
				if impGroups.ClusterWide || contains(impGroups.ClusterNames, n.Name) {
					g.addEdge(Edge{From: from, To: k, Technique: TechImpersonate,
						Detail:   "impersonate group " + n.Name + " (Impersonate-User + Impersonate-Group headers)",
						Evidence: append(evidence(impGroups, ""), evidence(impUsers, "")...)})
				}
			}
			for _, name := range impGroups.ClusterNames {
				to := g.addNode(rbac.GroupID(name))
				g.addEdge(Edge{From: from, To: to, Technique: TechImpersonate,
					Detail:   "impersonate group " + name + " (Impersonate-User + Impersonate-Group headers)",
					Evidence: append(evidence(impGroups, ""), evidence(impUsers, "")...)})
			}
		}
	}
	impSA := acc("impersonate", "", "serviceaccounts", "")
	if impSA.Any() {
		for _, ns := range nss {
			for _, sa := range e.ServiceAccounts(ns) {
				if impSA.AllowsName(ns, sa.Meta.Name) {
					saEdge(ns, sa.Meta.Name, TechImpersonate,
						fmt.Sprintf("impersonate serviceaccount %s/%s", ns, sa.Meta.Name), evidence(impSA, ns), false)
				}
			}
		}
	}

	// bind / escalate.
	g.rbacEdges(id, acc)

	// Token secrets.
	get := acc("get", "", "secrets", "")
	list := mergeAccess(acc("list", "", "secrets", ""), acc("watch", "", "secrets", ""))
	if get.Any() || list.Any() {
		for _, ns := range nss {
			for _, s := range e.TokenSecrets(ns) {
				saName := s.Meta.Annotations[model.AnnotationSAName]
				if saName == "" {
					continue
				}
				var ev []string
				switch {
				case list.InNamespace(ns):
					ev = evidence(list, ns)
				case get.AllowsName(ns, s.Meta.Name):
					ev = evidence(get, ns)
				default:
					continue
				}
				saEdge(ns, saName, TechReadSecret,
					fmt.Sprintf("read Secret %s/%s (type service-account-token) holding a token for %s", ns, s.Meta.Name, saName), ev, false)
			}
		}
	}

	// exec / attach into existing pods.
	exec := mergeAccess(acc("create", "", "pods", "exec"), acc("create", "", "pods", "attach"))
	if exec.Any() {
		for _, ns := range nss {
			for _, p := range e.Pods(ns) {
				if !e.AutomountEffective(p) {
					continue
				}
				if p.OwnerKind != "" {
					if !exec.InNamespace(ns) {
						continue
					}
				} else if !exec.AllowsName(ns, p.Meta.Name) {
					continue
				}
				saEdge(ns, p.ServiceAccountName, TechExecPod,
					fmt.Sprintf("exec into %s (runs as %s, token automounted) and read /var/run/secrets/kubernetes.io/serviceaccount/token", p.Ref(), p.ServiceAccountName),
					evidence(exec, ns), false)
			}
		}
	}

	// nodes/proxy -> kubelet -> pods on the node (approximate).
	np := mergeAccess(acc("get", "", "nodes", "proxy"), acc("create", "", "nodes", "proxy"))
	if np.Any() {
		for _, ns := range nss {
			for _, p := range e.Pods(ns) {
				if !e.AutomountEffective(p) {
					continue
				}
				switch {
				case np.ClusterWide:
				case p.NodeName != "" && contains(np.ClusterNames, p.NodeName):
				default:
					continue
				}
				where := "the node running it"
				if p.NodeName != "" {
					where = "node " + p.NodeName
				}
				saEdge(ns, p.ServiceAccountName, TechNodeProxy,
					fmt.Sprintf("use nodes/proxy on %s to exec into %s via the kubelet API and read the %s token", where, p.Ref(), p.ServiceAccountName),
					evidence(np, ""), true)
			}
		}
	}

	// CSR create + approve + signer approve -> system:masters.
	csrCreate := acc("create", "certificates.k8s.io", "certificatesigningrequests", "")
	csrApprove := mergeAccess(acc("update", "certificates.k8s.io", "certificatesigningrequests", "approval"),
		acc("patch", "certificates.k8s.io", "certificatesigningrequests", "approval"))
	signer := acc("approve", "certificates.k8s.io", "signers", "")
	if csrCreate.ClusterWide && csrApprove.Any() &&
		(signer.ClusterWide || contains(signer.ClusterNames, "kubernetes.io/kube-apiserver-client") || contains(signer.ClusterNames, "kubernetes.io/*")) {
		to := g.addNode(rbac.GroupID(rbac.GroupMasters))
		g.addEdge(Edge{From: from, To: to, Technique: TechCSR,
			Detail:   "create a CSR for O=system:masters with signerName kubernetes.io/kube-apiserver-client and approve it",
			Evidence: append(append(evidence(csrCreate, ""), evidence(csrApprove, "")...), evidence(signer, "")...)})
	}
}

func (g *Graph) rbacEdges(id rbac.Identity, acc func(verb, group, res, sub string) *rbac.Access) {
	e := g.e
	from := id.Key()
	const rg = "rbac.authorization.k8s.io"
	bindCR := acc("bind", rg, "clusterroles", "")
	createCRB := acc("create", rg, "clusterrolebindings", "")
	escalateCR := acc("escalate", rg, "clusterroles", "")
	if !bindCR.Any() && !escalateCR.Any() && !createCRB.Any() && !acc("create", rg, "rolebindings", "").Any() {
		return
	}
	// bindable returns the first candidate ClusterRole the identity may bind
	// cluster-wide (ns == "") or in ns.
	bindable := func(candidates []*model.Role, ns string) *model.Role {
		for _, r := range candidates {
			if ns == "" {
				if bindCR.ClusterWide || contains(bindCR.ClusterNames, r.Meta.Name) {
					return r
				}
			} else if bindCR.AllowsName(ns, r.Meta.Name) {
				return r
			}
		}
		return nil
	}
	if createCRB.ClusterWide {
		if r := bindable(g.adminRoles, ""); r != nil {
			g.addEdge(Edge{From: from, To: AdminNode, Technique: TechBindRole,
				Detail:   fmt.Sprintf("create a ClusterRoleBinding of ClusterRole %s to itself (bind permitted)", r.Meta.Name),
				Evidence: append(evidence(createCRB, ""), evidence(bindCR, "")...)})
		} else if escalateCR.ClusterWide && acc("create", rg, "clusterroles", "").ClusterWide {
			g.addEdge(Edge{From: from, To: AdminNode, Technique: TechEscalateRole,
				Detail:   "create a ClusterRole with */*/* (escalate permitted) and a ClusterRoleBinding to itself",
				Evidence: append(evidence(createCRB, ""), evidence(escalateCR, "")...)})
		}
	}
	// escalate + update on a ClusterRole already bound to the identity cluster-wide.
	if escalateCR.Any() {
		upd := mergeAccess(acc("update", rg, "clusterroles", ""), acc("patch", rg, "clusterroles", ""))
		// Prefer roles bound to the identity directly over roles it holds
		// through broad groups such as system:authenticated.
		grants := e.GrantsFor(id)
		ordered := make([]rbac.Grant, 0, len(grants))
		for _, direct := range []bool{true, false} {
			for _, gr := range grants {
				if (rbac.IdentityFromSubject(gr.Subject).Key() == id.Key()) == direct {
					ordered = append(ordered, gr)
				}
			}
		}
		for _, gr := range ordered {
			if !gr.ClusterWide() || gr.Role.Kind != model.KindClusterRole {
				continue
			}
			name := gr.Role.Meta.Name
			if (escalateCR.ClusterWide || contains(escalateCR.ClusterNames, name)) && (upd.ClusterWide || contains(upd.ClusterNames, name)) {
				g.addEdge(Edge{From: from, To: AdminNode, Technique: TechEscalateRole,
					Detail:   fmt.Sprintf("add */*/* to ClusterRole %s, which is bound to it by %s", name, gr.Binding.Ref()),
					Evidence: append(evidence(escalateCR, ""), evidence(upd, "")...)})
				break
			}
		}
	}
	// Bind a role that can create pods (cluster-wide or in a namespace), then
	// create a pod as any service account of the namespace.
	createRB := acc("create", rg, "rolebindings", "")
	bindRole := acc("bind", rg, "roles", "")
	escRole := acc("escalate", rg, "roles", "")
	createRole := acc("create", rg, "roles", "")
	var clusterHow string
	var clusterEv []string
	if createCRB.ClusterWide {
		if r := bindable(g.podCreators, ""); r != nil {
			clusterHow = fmt.Sprintf("create a ClusterRoleBinding of ClusterRole %s (which can create pods) to itself, then create a pod", r.Meta.Name)
			clusterEv = append(evidence(createCRB, ""), evidence(bindCR, "")...)
		}
	}
	for _, ns := range e.Namespaces() {
		how, ev := clusterHow, clusterEv
		if how == "" && createRB.InNamespace(ns) {
			ev = append(evidence(createRB, ns), evidence(bindCR, ns)...)
			if r := bindable(g.podCreators, ns); r != nil {
				how = fmt.Sprintf("create a RoleBinding of ClusterRole %s (which can create pods) to itself in namespace %s, then create a pod", r.Meta.Name, ns)
			} else if escRole.InNamespace(ns) && createRole.InNamespace(ns) {
				how = fmt.Sprintf("create a Role that can create pods in namespace %s (escalate permitted), bind it to itself, then create a pod", ns)
				ev = append(ev, evidence(escRole, ns)...)
			} else if bindRole.InNamespace(ns) {
				for _, r := range e.Cluster.Roles {
					if r.Meta.Namespace == ns && g.canCreatePods(r) {
						how = fmt.Sprintf("create a RoleBinding of Role %s (which can create pods) to itself in namespace %s, then create a pod", r.Meta.Name, ns)
						ev = append(ev, evidence(bindRole, ns)...)
						break
					}
				}
			}
		}
		if how == "" {
			continue
		}
		for _, sa := range e.ServiceAccounts(ns) {
			to := rbac.SAID(ns, sa.Meta.Name)
			g.addNode(to)
			g.addEdge(Edge{From: from, To: to.Key(), Technique: TechBindRole,
				Detail: how + " as " + sa.Meta.Name, Evidence: ev})
		}
	}
}

var createPodAttrs = rbac.Attributes{Verb: "create", Resource: "pods"}

func (g *Graph) canCreatePods(r *model.Role) bool {
	for _, er := range g.e.Rules(r) {
		if ok, _ := rbac.RuleAllowsAnyName(createPodAttrs, &er.Rule); ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Path is a shortest escalation path from a source to the target.
type Path struct {
	Source rbac.Identity `json:"source"`
	Target string        `json:"target"`
	Hops   []Edge        `json:"hops"`
}

// Approximate reports whether any hop is approximate.
func (p Path) Approximate() bool {
	for _, h := range p.Hops {
		if h.Approximate {
			return true
		}
	}
	return false
}

// Shortest returns a shortest escalation path from src to target (a node
// key, e.g. AdminNode or "sa:ns/name"), or nil if target is unreachable.
//
// Paths that use only exact edges are preferred: approximate edges (e.g.
// nodes/proxy) are used only when no exact path exists. Among equally short
// paths the choice is deterministic (edges are ordered by target key and
// technique priority).
func (g *Graph) Shortest(src, target string) []Edge {
	if src == target {
		return []Edge{}
	}
	if hops := g.walk(src, target, g.distancesTo(target, false), false); hops != nil {
		return hops
	}
	return g.walk(src, target, g.distancesTo(target, true), true)
}

// distancesTo runs a single reverse BFS from target and returns, for every
// node that can reach it, the number of hops on a shortest path.
func (g *Graph) distancesTo(target string, allowApprox bool) map[string]int {
	rev := map[string][]string{}
	for from, edges := range g.Out {
		for _, ed := range edges {
			if ed.Approximate && !allowApprox {
				continue
			}
			rev[ed.To] = append(rev[ed.To], from)
		}
	}
	dist := map[string]int{target: 0}
	queue := []string{target}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, from := range rev[n] {
			if _, seen := dist[from]; seen {
				continue
			}
			dist[from] = dist[n] + 1
			queue = append(queue, from)
		}
	}
	return dist
}

// walk follows, from src, the first edge that decreases the distance to the
// target by one.
func (g *Graph) walk(src, target string, dist map[string]int, allowApprox bool) []Edge {
	if _, ok := dist[src]; !ok {
		return nil
	}
	hops := []Edge{}
	for n := src; n != target; {
		next := false
		for _, ed := range g.Out[n] {
			if ed.Approximate && !allowApprox {
				continue
			}
			if d, ok := dist[ed.To]; ok && d == dist[n]-1 {
				hops = append(hops, ed)
				n = ed.To
				next = true
				break
			}
		}
		if !next {
			return nil // unreachable by construction
		}
	}
	return hops
}

// FindOptions select sources and the target.
type FindOptions struct {
	From          []rbac.Identity // empty: every non-system node
	To            string          // node key; default AdminNode
	IncludeSystem bool
}

// Find returns shortest paths for each source that can reach the target,
// sorted by length then source. Sources that are the target are skipped.
func (g *Graph) Find(opts FindOptions) []Path {
	target := opts.To
	if target == "" {
		target = AdminNode
	}
	var sources []rbac.Identity
	if len(opts.From) > 0 {
		sources = opts.From
	} else {
		for _, k := range g.sortedKeys() {
			id := g.Nodes[k]
			if !opts.IncludeSystem && id.IsSystem() {
				continue
			}
			sources = append(sources, id)
		}
	}
	exact := g.distancesTo(target, false)
	approx := g.distancesTo(target, true)
	var out []Path
	for _, s := range sources {
		k := s.Key()
		if k == target {
			continue
		}
		hops := g.walk(k, target, exact, false)
		if hops == nil {
			hops = g.walk(k, target, approx, true)
		}
		if hops == nil {
			continue
		}
		out = append(out, Path{Source: s, Target: target, Hops: hops})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].Hops) != len(out[j].Hops) {
			return len(out[i].Hops) < len(out[j].Hops)
		}
		return out[i].Source.Key() < out[j].Source.Key()
	})
	return out
}

// EdgeCount returns the total number of edges.
func (g *Graph) EdgeCount() int {
	n := 0
	for _, es := range g.Out {
		n += len(es)
	}
	return n
}
