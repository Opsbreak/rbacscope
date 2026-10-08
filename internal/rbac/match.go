// Package rbac implements an offline model of the Kubernetes RBAC authorizer:
// rule matching, ClusterRole aggregation, binding scoping, subject matching,
// who-can and effective-permission queries.
//
// Matching functions mirror k8s.io/kubernetes/pkg/apis/rbac/v1/evaluation_helpers.go.
package rbac

import (
	"strings"

	"github.com/Opsbreak/rbacscope/internal/model"
)

// Attributes describe a single authorization request.
type Attributes struct {
	Verb        string
	APIGroup    string
	Resource    string
	Subresource string
	Name        string
	// Namespace of the request. Empty means a cluster-scoped request (or a
	// request across all namespaces, e.g. "list secrets -A").
	Namespace string
	// Path is set for non-resource requests (e.g. "/metrics").
	Path string
}

// IsResourceRequest reports whether the attributes target an API resource.
func (a Attributes) IsResourceRequest() bool { return a.Path == "" }

// CombinedResource returns "resource" or "resource/subresource".
func (a Attributes) CombinedResource() string {
	if a.Subresource == "" {
		return a.Resource
	}
	return a.Resource + "/" + a.Subresource
}

// String renders the request for humans.
func (a Attributes) String() string {
	if !a.IsResourceRequest() {
		return a.Verb + " " + a.Path
	}
	s := a.Verb + " " + a.CombinedResource()
	if a.APIGroup != "" {
		s += " (" + a.APIGroup + ")"
	}
	if a.Name != "" {
		s += " name=" + a.Name
	}
	return s
}

// Wildcards used in RBAC rules.
const (
	VerbAll     = "*"
	APIGroupAll = "*"
	ResourceAll = "*"
	NonResAll   = "*"
)

// VerbMatches reports whether rule grants the requested verb.
func VerbMatches(rule *model.PolicyRule, verb string) bool {
	for _, v := range rule.Verbs {
		if v == VerbAll || v == verb {
			return true
		}
	}
	return false
}

// APIGroupMatches reports whether rule covers the requested API group.
func APIGroupMatches(rule *model.PolicyRule, group string) bool {
	for _, g := range rule.APIGroups {
		if g == APIGroupAll || g == group {
			return true
		}
	}
	return false
}

// ResourceMatches implements the upstream semantics: "*" matches everything,
// exact "resource/subresource" matches, and "*/subresource" matches the
// subresource of any resource. Note that "pods" does NOT match "pods/exec",
// and "pods/*" is not a wildcard.
func ResourceMatches(rule *model.PolicyRule, combined, subresource string) bool {
	for _, r := range rule.Resources {
		if r == ResourceAll || r == combined {
			return true
		}
		if subresource == "" {
			continue
		}
		if len(r) == len(subresource)+2 && strings.HasPrefix(r, "*/") && strings.HasSuffix(r, subresource) {
			return true
		}
	}
	return false
}

// ResourceNameMatches reports whether rule covers the requested object name.
// A rule without resourceNames covers all names; a rule with resourceNames
// never matches a request without a name (list, watch, create, ...).
func ResourceNameMatches(rule *model.PolicyRule, name string) bool {
	if len(rule.ResourceNames) == 0 {
		return true
	}
	for _, n := range rule.ResourceNames {
		if n == name {
			return true
		}
	}
	return false
}

// NonResourceURLMatches matches a non-resource path; a trailing "*" in the
// rule is a prefix wildcard.
func NonResourceURLMatches(rule *model.PolicyRule, path string) bool {
	for _, u := range rule.NonResourceURLs {
		if u == NonResAll || u == path {
			return true
		}
		if strings.HasSuffix(u, "*") && strings.HasPrefix(path, strings.TrimRight(u, "*")) {
			return true
		}
	}
	return false
}

// RuleAllows reports whether a single rule authorizes the request.
func RuleAllows(a Attributes, rule *model.PolicyRule) bool {
	if a.IsResourceRequest() {
		return VerbMatches(rule, a.Verb) &&
			APIGroupMatches(rule, a.APIGroup) &&
			ResourceMatches(rule, a.CombinedResource(), a.Subresource) &&
			ResourceNameMatches(rule, a.Name)
	}
	return VerbMatches(rule, a.Verb) && NonResourceURLMatches(rule, a.Path)
}

// RuleAllowsAnyName is like RuleAllows but ignores resourceNames. It returns
// (allowed, restricted) where restricted reports that the rule is limited to
// specific object names. Used by the auditor and path finder, which care
// about "some" access, not access to one particular object.
func RuleAllowsAnyName(a Attributes, rule *model.PolicyRule) (allowed, restricted bool) {
	if !a.IsResourceRequest() {
		return RuleAllows(a, rule), false
	}
	if !VerbMatches(rule, a.Verb) || !APIGroupMatches(rule, a.APIGroup) || !ResourceMatches(rule, a.CombinedResource(), a.Subresource) {
		return false, false
	}
	restricted = len(rule.ResourceNames) > 0
	if restricted && a.Subresource == "" && (a.Verb == "create" || a.Verb == "deletecollection") {
		// Top-level create/deletecollection requests carry no object name, so
		// a resourceNames-restricted rule can never authorize them.
		return false, false
	}
	return true, restricted
}

// ClusterScopedRequest reports whether a request template is evaluated
// without a namespace, so that only ClusterRoleBindings apply. The special
// case is "bind" on clusterroles, which the API server checks in the
// namespace of the RoleBinding being created.
func ClusterScopedRequest(a Attributes) bool {
	if !a.IsResourceRequest() {
		return true
	}
	if a.Verb == "bind" && a.Resource == "clusterroles" && a.Subresource == "" {
		return false
	}
	return IsClusterScoped(a.Resource)
}

// IsFullWildcard reports whether a rule is equivalent to cluster-admin's
// resource rule: all verbs on all resources in all API groups, any name.
func IsFullWildcard(rule *model.PolicyRule) bool {
	return contains(rule.Verbs, VerbAll) && contains(rule.APIGroups, APIGroupAll) &&
		contains(rule.Resources, ResourceAll) && len(rule.ResourceNames) == 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// SelectorMatches evaluates a metav1.LabelSelector against labels. An empty
// selector matches everything, mirroring metav1.LabelSelectorAsSelector.
// Unknown operators never match.
func SelectorMatches(sel model.LabelSelector, labels map[string]string) bool {
	for k, v := range sel.MatchLabels {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	for _, req := range sel.MatchExpressions {
		lv, has := labels[req.Key]
		switch req.Operator {
		case "In":
			if !has || !contains(req.Values, lv) {
				return false
			}
		case "NotIn":
			if has && contains(req.Values, lv) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}
