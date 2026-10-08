package rbac

import "strings"

// builtinGroups maps well-known resource names to their API group. Used to
// resolve user queries like "who-can get deployments" (RBAC rules are matched
// on apiGroup, so the group must be known).
var builtinGroups = map[string]string{
	// core
	"pods": "", "services": "", "endpoints": "", "configmaps": "", "secrets": "",
	"serviceaccounts": "", "namespaces": "", "nodes": "", "persistentvolumes": "",
	"persistentvolumeclaims": "", "events": "", "limitranges": "", "resourcequotas": "",
	"replicationcontrollers": "", "podtemplates": "", "componentstatuses": "", "bindings": "",
	"users": "", "groups": "", "uids": "", "userextras": "",
	// apps
	"deployments": "apps", "statefulsets": "apps", "daemonsets": "apps", "replicasets": "apps",
	"controllerrevisions": "apps",
	// batch
	"jobs": "batch", "cronjobs": "batch",
	// rbac
	"roles": "rbac.authorization.k8s.io", "clusterroles": "rbac.authorization.k8s.io",
	"rolebindings": "rbac.authorization.k8s.io", "clusterrolebindings": "rbac.authorization.k8s.io",
	// certificates
	"certificatesigningrequests": "certificates.k8s.io", "signers": "certificates.k8s.io",
	// admission
	"mutatingwebhookconfigurations":     "admissionregistration.k8s.io",
	"validatingwebhookconfigurations":   "admissionregistration.k8s.io",
	"validatingadmissionpolicies":       "admissionregistration.k8s.io",
	"validatingadmissionpolicybindings": "admissionregistration.k8s.io",
	"mutatingadmissionpolicies":         "admissionregistration.k8s.io",
	"mutatingadmissionpolicybindings":   "admissionregistration.k8s.io",
	"customresourcedefinitions":         "apiextensions.k8s.io",
	"apiservices":                       "apiregistration.k8s.io",
	"tokenreviews":                      "authentication.k8s.io",
	"subjectaccessreviews":              "authorization.k8s.io",
	"selfsubjectaccessreviews":          "authorization.k8s.io",
	"selfsubjectrulesreviews":           "authorization.k8s.io",
	"localsubjectaccessreviews":         "authorization.k8s.io",
	"storageclasses":                    "storage.k8s.io",
	"volumeattachments":                 "storage.k8s.io",
	"csidrivers":                        "storage.k8s.io",
	"csinodes":                          "storage.k8s.io",
	"ingresses":                         "networking.k8s.io",
	"ingressclasses":                    "networking.k8s.io",
	"networkpolicies":                   "networking.k8s.io",
	"poddisruptionbudgets":              "policy",
	"podsecuritypolicies":               "policy",
	"priorityclasses":                   "scheduling.k8s.io",
	"leases":                            "coordination.k8s.io",
	"horizontalpodautoscalers":          "autoscaling",
	"endpointslices":                    "discovery.k8s.io",
	"runtimeclasses":                    "node.k8s.io",
	"flowschemas":                       "flowcontrol.apiserver.k8s.io",
	"prioritylevelconfigurations":       "flowcontrol.apiserver.k8s.io",
	"clustertrustbundles":               "certificates.k8s.io",
	"resourceclaims":                    "resource.k8s.io",
	"deviceclasses":                     "resource.k8s.io",
}

// clusterScoped lists well-known cluster-scoped resources. RoleBindings never
// grant access to these (a RoleBinding is always evaluated in its namespace).
var clusterScoped = map[string]bool{
	"nodes": true, "namespaces": true, "persistentvolumes": true, "componentstatuses": true,
	"clusterroles": true, "clusterrolebindings": true, "certificatesigningrequests": true,
	"signers": true, "mutatingwebhookconfigurations": true, "validatingwebhookconfigurations": true,
	"validatingadmissionpolicies": true, "validatingadmissionpolicybindings": true,
	"mutatingadmissionpolicies": true, "mutatingadmissionpolicybindings": true,
	"customresourcedefinitions": true, "apiservices": true, "tokenreviews": true,
	"subjectaccessreviews": true, "selfsubjectaccessreviews": true, "selfsubjectrulesreviews": true,
	"storageclasses": true, "volumeattachments": true, "csidrivers": true, "csinodes": true,
	"ingressclasses": true, "podsecuritypolicies": true, "priorityclasses": true,
	"runtimeclasses": true, "flowschemas": true, "prioritylevelconfigurations": true,
	"clustertrustbundles": true, "deviceclasses": true,
	// impersonation targets other than serviceaccounts are cluster scoped
	"users": true, "groups": true, "uids": true, "userextras": true,
}

// ResolveResource splits a user supplied resource spec such as "pods/exec",
// "deployments.apps" or "widgets.example.com/status" into resource,
// subresource and API group. explicitGroup (if non-empty, or "core") wins.
// known reports whether the group was resolved from the builtin table or
// supplied explicitly.
func ResolveResource(spec, explicitGroup string) (resource, subresource, group string, known bool) {
	resource = spec
	if i := strings.Index(resource, "/"); i >= 0 {
		subresource = resource[i+1:]
		resource = resource[:i]
	}
	if explicitGroup != "" {
		if explicitGroup == "core" {
			explicitGroup = ""
		}
		return resource, subresource, explicitGroup, true
	}
	if i := strings.Index(resource, "."); i >= 0 {
		return resource[:i], subresource, resource[i+1:], true
	}
	g, ok := builtinGroups[resource]
	return resource, subresource, g, ok
}

// IsClusterScoped reports whether a resource is cluster scoped.
func IsClusterScoped(resource string) bool {
	return clusterScoped[resource]
}
