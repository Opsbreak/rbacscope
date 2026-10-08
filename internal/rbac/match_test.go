package rbac

import (
	"testing"

	"github.com/Opsbreak/rbacscope/internal/model"
)

func rule(verbs, groups, resources []string) model.PolicyRule {
	return model.PolicyRule{Verbs: verbs, APIGroups: groups, Resources: resources}
}

func s(v ...string) []string { return v }

func TestRuleAllows(t *testing.T) {
	core := s("")
	tests := []struct {
		name string
		rule model.PolicyRule
		a    Attributes
		want bool
	}{
		{"exact match", rule(s("get"), core, s("pods")), Attributes{Verb: "get", Resource: "pods"}, true},
		{"verb mismatch", rule(s("get"), core, s("pods")), Attributes{Verb: "delete", Resource: "pods"}, false},
		{"verb wildcard", rule(s("*"), core, s("pods")), Attributes{Verb: "delete", Resource: "pods"}, true},
		{"group mismatch", rule(s("get"), s("apps"), s("pods")), Attributes{Verb: "get", Resource: "pods"}, false},
		{"group wildcard", rule(s("get"), s("*"), s("deployments")), Attributes{Verb: "get", APIGroup: "apps", Resource: "deployments"}, true},
		{"no groups never matches", rule(s("get"), nil, s("pods")), Attributes{Verb: "get", Resource: "pods"}, false},
		{"resource wildcard", rule(s("get"), core, s("*")), Attributes{Verb: "get", Resource: "secrets"}, true},
		{"resource wildcard covers subresource", rule(s("create"), core, s("*")), Attributes{Verb: "create", Resource: "pods", Subresource: "exec"}, true},
		{"resource does not cover subresource", rule(s("create"), core, s("pods")), Attributes{Verb: "create", Resource: "pods", Subresource: "exec"}, false},
		{"exact subresource", rule(s("create"), core, s("pods/exec")), Attributes{Verb: "create", Resource: "pods", Subresource: "exec"}, true},
		{"subresource rule does not cover parent", rule(s("get"), core, s("pods/log")), Attributes{Verb: "get", Resource: "pods"}, false},
		{"star-slash-subresource", rule(s("get"), core, s("*/status")), Attributes{Verb: "get", Resource: "nodes", Subresource: "status"}, true},
		{"star-slash-subresource other sub", rule(s("get"), core, s("*/status")), Attributes{Verb: "get", Resource: "nodes", Subresource: "proxy"}, false},
		{"pods/* is not a wildcard", rule(s("create"), core, s("pods/*")), Attributes{Verb: "create", Resource: "pods", Subresource: "exec"}, false},
		{"nodes/proxy", rule(s("get"), core, s("nodes/proxy")), Attributes{Verb: "get", Resource: "nodes", Subresource: "proxy"}, true},
		{"serviceaccounts/token", rule(s("create"), core, s("serviceaccounts/token")), Attributes{Verb: "create", Resource: "serviceaccounts", Subresource: "token", Name: "x"}, true},
		{"resourceNames match", model.PolicyRule{Verbs: s("get"), APIGroups: core, Resources: s("secrets"), ResourceNames: s("a", "b")}, Attributes{Verb: "get", Resource: "secrets", Name: "b"}, true},
		{"resourceNames mismatch", model.PolicyRule{Verbs: s("get"), APIGroups: core, Resources: s("secrets"), ResourceNames: s("a")}, Attributes{Verb: "get", Resource: "secrets", Name: "c"}, false},
		{"resourceNames vs list without name", model.PolicyRule{Verbs: s("list"), APIGroups: core, Resources: s("secrets"), ResourceNames: s("a")}, Attributes{Verb: "list", Resource: "secrets"}, false},
		{"no resourceNames covers any name", rule(s("get"), core, s("secrets")), Attributes{Verb: "get", Resource: "secrets", Name: "anything"}, true},
		{"resource rule does not match non-resource", rule(s("get"), core, s("*")), Attributes{Verb: "get", Path: "/metrics"}, false},
		{"non-resource exact", model.PolicyRule{Verbs: s("get"), NonResourceURLs: s("/metrics")}, Attributes{Verb: "get", Path: "/metrics"}, true},
		{"non-resource prefix star", model.PolicyRule{Verbs: s("get"), NonResourceURLs: s("/api/*")}, Attributes{Verb: "get", Path: "/api/v1"}, true},
		{"non-resource prefix star matches bare prefix", model.PolicyRule{Verbs: s("get"), NonResourceURLs: s("/api/*")}, Attributes{Verb: "get", Path: "/api/"}, true},
		{"non-resource prefix star no match", model.PolicyRule{Verbs: s("get"), NonResourceURLs: s("/api/*")}, Attributes{Verb: "get", Path: "/apis/apps"}, false},
		{"non-resource wildcard", model.PolicyRule{Verbs: s("*"), NonResourceURLs: s("*")}, Attributes{Verb: "post", Path: "/anything"}, true},
		{"non-resource verb mismatch", model.PolicyRule{Verbs: s("get"), NonResourceURLs: s("/healthz")}, Attributes{Verb: "post", Path: "/healthz"}, false},
		{"non-resource rule never matches resource", model.PolicyRule{Verbs: s("*"), NonResourceURLs: s("*")}, Attributes{Verb: "get", Resource: "pods"}, false},
		{"impersonate users", rule(s("impersonate"), core, s("users")), Attributes{Verb: "impersonate", Resource: "users", Name: "admin"}, true},
		{"escalate verb", rule(s("escalate"), s("rbac.authorization.k8s.io"), s("clusterroles")), Attributes{Verb: "escalate", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterroles"}, true},
		{"empty verbs", rule(nil, core, s("pods")), Attributes{Verb: "get", Resource: "pods"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.rule
			if got := RuleAllows(tt.a, &r); got != tt.want {
				t.Fatalf("RuleAllows(%v, %+v) = %v, want %v", tt.a, tt.rule, got, tt.want)
			}
		})
	}
}

func TestRuleAllowsAnyName(t *testing.T) {
	named := model.PolicyRule{Verbs: s("get", "create", "list"), APIGroups: s(""), Resources: s("secrets", "pods/exec", "pods"), ResourceNames: s("x")}
	tests := []struct {
		name           string
		a              Attributes
		ok, restricted bool
	}{
		{"get restricted", Attributes{Verb: "get", Resource: "secrets"}, true, true},
		{"list restricted", Attributes{Verb: "list", Resource: "secrets"}, true, true},
		{"top-level create can never use names", Attributes{Verb: "create", Resource: "pods"}, false, false},
		{"subresource create carries parent name", Attributes{Verb: "create", Resource: "pods", Subresource: "exec"}, true, true},
		{"verb mismatch", Attributes{Verb: "delete", Resource: "secrets"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, restricted := RuleAllowsAnyName(tt.a, &named)
			if ok != tt.ok || restricted != tt.restricted {
				t.Fatalf("got (%v,%v), want (%v,%v)", ok, restricted, tt.ok, tt.restricted)
			}
		})
	}
}

func TestSelectorMatches(t *testing.T) {
	labels := map[string]string{"a": "1", "b": "2"}
	tests := []struct {
		name string
		sel  model.LabelSelector
		want bool
	}{
		{"empty selector matches everything", model.LabelSelector{}, true},
		{"matchLabels hit", model.LabelSelector{MatchLabels: map[string]string{"a": "1"}}, true},
		{"matchLabels value miss", model.LabelSelector{MatchLabels: map[string]string{"a": "2"}}, false},
		{"matchLabels key miss", model.LabelSelector{MatchLabels: map[string]string{"c": "1"}}, false},
		{"In hit", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "a", Operator: "In", Values: s("0", "1")}}}, true},
		{"In miss", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "a", Operator: "In", Values: s("0")}}}, false},
		{"In missing key", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "z", Operator: "In", Values: s("1")}}}, false},
		{"NotIn hit", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "a", Operator: "NotIn", Values: s("1")}}}, false},
		{"NotIn missing key matches", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "z", Operator: "NotIn", Values: s("1")}}}, true},
		{"Exists", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "b", Operator: "Exists"}}}, true},
		{"DoesNotExist", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "b", Operator: "DoesNotExist"}}}, false},
		{"unknown operator", model.LabelSelector{MatchExpressions: []model.LabelSelectorRequirement{{Key: "a", Operator: "Gt"}}}, false},
		{"labels and expressions ANDed", model.LabelSelector{MatchLabels: map[string]string{"a": "1"}, MatchExpressions: []model.LabelSelectorRequirement{{Key: "b", Operator: "DoesNotExist"}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectorMatches(tt.sel, labels); got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}

func TestResolveResource(t *testing.T) {
	tests := []struct {
		spec, group     string
		res, sub, wantG string
		known           bool
	}{
		{"pods", "", "pods", "", "", true},
		{"pods/exec", "", "pods", "exec", "", true},
		{"deployments", "", "deployments", "", "apps", true},
		{"deployments.apps", "", "deployments", "", "apps", true},
		{"widgets.example.com/status", "", "widgets", "status", "example.com", true},
		{"widgets", "", "widgets", "", "", false},
		{"widgets", "example.com", "widgets", "", "example.com", true},
		{"pods", "core", "pods", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.spec+"|"+tt.group, func(t *testing.T) {
			r, sub, g, known := ResolveResource(tt.spec, tt.group)
			if r != tt.res || sub != tt.sub || g != tt.wantG || known != tt.known {
				t.Fatalf("got (%q,%q,%q,%v)", r, sub, g, known)
			}
		})
	}
}
