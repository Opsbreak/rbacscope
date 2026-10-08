// Package model defines the minimal subset of Kubernetes object types that
// rbacscope needs. It intentionally avoids depending on client-go/apimachinery.
package model

import "fmt"

// Source records where an object was read from.
type Source struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

func (s Source) String() string {
	if s.File == "" {
		return "<unknown>"
	}
	if s.Line > 0 {
		return fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	return s.File
}

// ObjectMeta is the subset of metav1.ObjectMeta used by rbacscope.
type ObjectMeta struct {
	Name        string            `yaml:"name" json:"name"`
	Namespace   string            `yaml:"namespace,omitempty" json:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// PolicyRule mirrors rbac.authorization.k8s.io/v1 PolicyRule.
type PolicyRule struct {
	Verbs           []string `yaml:"verbs" json:"verbs"`
	APIGroups       []string `yaml:"apiGroups,omitempty" json:"apiGroups,omitempty"`
	Resources       []string `yaml:"resources,omitempty" json:"resources,omitempty"`
	ResourceNames   []string `yaml:"resourceNames,omitempty" json:"resourceNames,omitempty"`
	NonResourceURLs []string `yaml:"nonResourceURLs,omitempty" json:"nonResourceURLs,omitempty"`
}

// LabelSelectorRequirement mirrors metav1.LabelSelectorRequirement.
type LabelSelectorRequirement struct {
	Key      string   `yaml:"key" json:"key"`
	Operator string   `yaml:"operator" json:"operator"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"`
}

// LabelSelector mirrors metav1.LabelSelector.
type LabelSelector struct {
	MatchLabels      map[string]string          `yaml:"matchLabels,omitempty" json:"matchLabels,omitempty"`
	MatchExpressions []LabelSelectorRequirement `yaml:"matchExpressions,omitempty" json:"matchExpressions,omitempty"`
}

// AggregationRule mirrors rbac/v1 AggregationRule.
type AggregationRule struct {
	ClusterRoleSelectors []LabelSelector `yaml:"clusterRoleSelectors" json:"clusterRoleSelectors"`
}

// Role kinds.
const (
	KindRole               = "Role"
	KindClusterRole        = "ClusterRole"
	KindRoleBinding        = "RoleBinding"
	KindClusterRoleBinding = "ClusterRoleBinding"
)

// Subject kinds.
const (
	SubjectUser           = "User"
	SubjectGroup          = "Group"
	SubjectServiceAccount = "ServiceAccount"
)

// Role is a Role or ClusterRole.
type Role struct {
	Kind            string           `json:"kind"`
	Meta            ObjectMeta       `json:"metadata"`
	Rules           []PolicyRule     `json:"rules"`
	AggregationRule *AggregationRule `json:"aggregationRule,omitempty"`
	Source          Source           `json:"source"`
}

// Ref returns "ClusterRole/name" or "Role/ns/name".
func (r *Role) Ref() string {
	if r.Kind == KindClusterRole {
		return KindClusterRole + "/" + r.Meta.Name
	}
	return KindRole + "/" + r.Meta.Namespace + "/" + r.Meta.Name
}

// RoleRef mirrors rbac/v1 RoleRef.
type RoleRef struct {
	APIGroup string `yaml:"apiGroup" json:"apiGroup"`
	Kind     string `yaml:"kind" json:"kind"`
	Name     string `yaml:"name" json:"name"`
}

// Subject mirrors rbac/v1 Subject.
type Subject struct {
	Kind      string `yaml:"kind" json:"kind"`
	APIGroup  string `yaml:"apiGroup,omitempty" json:"apiGroup,omitempty"`
	Name      string `yaml:"name" json:"name"`
	Namespace string `yaml:"namespace,omitempty" json:"namespace,omitempty"`
}

// Binding is a RoleBinding or ClusterRoleBinding.
type Binding struct {
	Kind     string     `json:"kind"`
	Meta     ObjectMeta `json:"metadata"`
	RoleRef  RoleRef    `json:"roleRef"`
	Subjects []Subject  `json:"subjects"`
	Source   Source     `json:"source"`
}

// Ref returns "ClusterRoleBinding/name" or "RoleBinding/ns/name".
func (b *Binding) Ref() string {
	if b.Kind == KindClusterRoleBinding {
		return KindClusterRoleBinding + "/" + b.Meta.Name
	}
	return KindRoleBinding + "/" + b.Meta.Namespace + "/" + b.Meta.Name
}

// RoleRefString renders the role reference of a binding.
func (b *Binding) RoleRefString() string {
	if b.RoleRef.Kind == KindRole {
		return KindRole + "/" + b.Meta.Namespace + "/" + b.RoleRef.Name
	}
	return b.RoleRef.Kind + "/" + b.RoleRef.Name
}

// ServiceAccount is the subset of v1 ServiceAccount used by rbacscope.
type ServiceAccount struct {
	Meta                         ObjectMeta `json:"metadata"`
	AutomountServiceAccountToken *bool      `json:"automountServiceAccountToken,omitempty"`
	Source                       Source     `json:"source"`
	// Implicit is true when the ServiceAccount was not present in the input but
	// is referenced by a pod or binding (e.g. the per-namespace "default" SA).
	Implicit bool `json:"implicit,omitempty"`
}

// Pod is a pod or a pod template owned by a workload controller.
type Pod struct {
	Meta                         ObjectMeta `json:"metadata"`
	ServiceAccountName           string     `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool      `json:"automountServiceAccountToken,omitempty"`
	NodeName                     string     `json:"nodeName,omitempty"`
	Privileged                   bool       `json:"privileged,omitempty"`
	HostPath                     bool       `json:"hostPath,omitempty"`
	// OwnerKind/OwnerName are set when this entry is derived from a workload's
	// pod template (Deployment, DaemonSet, ...). Empty for bare pods.
	OwnerKind string `json:"ownerKind,omitempty"`
	OwnerName string `json:"ownerName,omitempty"`
	Source    Source `json:"source"`
}

// Ref renders a human readable reference to the pod or workload.
func (p *Pod) Ref() string {
	if p.OwnerKind != "" {
		return p.OwnerKind + "/" + p.Meta.Namespace + "/" + p.OwnerName
	}
	return "Pod/" + p.Meta.Namespace + "/" + p.Meta.Name
}

// Secret holds only metadata of a Secret. Secret data is never decoded.
type Secret struct {
	Meta   ObjectMeta `json:"metadata"`
	Type   string     `json:"type"`
	Source Source     `json:"source"`
}

// SecretTypeSAToken is the type of legacy service account token secrets.
const SecretTypeSAToken = "kubernetes.io/service-account-token"

// AnnotationSAName names the ServiceAccount a token secret belongs to.
const AnnotationSAName = "kubernetes.io/service-account.name"

// Namespace is a v1 Namespace.
type Namespace struct {
	Meta   ObjectMeta `json:"metadata"`
	Source Source     `json:"source"`
}

// Cluster is the full set of objects loaded from manifests.
type Cluster struct {
	Roles               []*Role
	ClusterRoles        []*Role
	RoleBindings        []*Binding
	ClusterRoleBindings []*Binding
	ServiceAccounts     []*ServiceAccount
	Pods                []*Pod
	Secrets             []*Secret
	Namespaces          []*Namespace
	// Warnings collects non-fatal problems found while loading.
	Warnings []string
	// Skipped counts objects of kinds rbacscope does not model.
	Skipped map[string]int
}

// BoolPtr is a helper for tests and generators.
func BoolPtr(b bool) *bool { return &b }
