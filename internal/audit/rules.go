package audit

// Rule describes an audit rule.
type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Severity    Severity `json:"defaultSeverity"`
}

// Rules is the catalogue of audit rules, in ID order.
var Rules = []Rule{
	{
		ID: "RS001", Name: "cluster-admin-equivalent", Severity: Critical,
		Title:       "Binding grants full wildcard access (*/*/*)",
		Description: "The bound role allows every verb on every resource in every API group. Through a ClusterRoleBinding this is cluster-admin; through a RoleBinding it is full control of the namespace, including its secrets and service accounts.",
		Remediation: "Replace the wildcard rule with the specific verbs/resources required. Reserve cluster-admin for break-glass identities and bind it through short-lived, audited access.",
	},
	{
		ID: "RS002", Name: "wildcard-rule", Severity: Medium,
		Title:       "Rule uses wildcards for verbs, resources or API groups",
		Description: "Wildcards automatically extend to subresources, new verbs and resources added by CRDs or future Kubernetes versions, so the effective permission silently grows over time.",
		Remediation: "Enumerate the verbs, apiGroups and resources explicitly.",
	},
	{
		ID: "RS003", Name: "rbac-escalate-bind", Severity: Critical,
		Title:       "Subject can escalate or bind roles",
		Description: "The escalate verb lets a subject create or update roles containing permissions it does not hold; bind lets it create bindings to roles it does not hold. Either bypasses RBAC privilege-escalation prevention (e.g. binding itself to cluster-admin).",
		Remediation: "Remove escalate/bind. If delegation is required, restrict bind with resourceNames to the specific low-privilege roles that may be delegated.",
	},
	{
		ID: "RS004", Name: "impersonation", Severity: Critical,
		Title:       "Subject can impersonate other identities",
		Description: "impersonate on users, groups, uids or serviceaccounts lets the subject act as any of those identities, e.g. as a member of system:masters.",
		Remediation: "Remove impersonate or restrict it with resourceNames to specific, low-privilege identities.",
	},
	{
		ID: "RS005", Name: "workload-creation", Severity: High,
		Title:       "Subject can create pods or modify workloads",
		Description: "Anyone who can create pods (directly or through Deployments, DaemonSets, Jobs, ...) in a namespace can run a pod as ANY service account in that namespace and read its token, inheriting all of that service account's permissions. They can also mount secrets and configmaps of the namespace.",
		Remediation: "Grant workload creation only in namespaces whose service accounts are no more privileged than the subject. Keep privileged service accounts in dedicated namespaces; enforce Pod Security Admission and an admission policy restricting serviceAccountName.",
	},
	{
		ID: "RS006", Name: "pod-exec-attach", Severity: High,
		Title:       "Subject can exec/attach into pods",
		Description: "pods/exec and pods/attach give a shell in running containers and therefore access to their mounted service account tokens, secrets and network position. (On clusters before 1.31, get on pods/exec also permits exec over WebSocket.)",
		Remediation: "Remove pods/exec and pods/attach from routine roles; use just-in-time access for debugging.",
	},
	{
		ID: "RS007", Name: "nodes-proxy", Severity: Critical,
		Title:       "Subject can access the kubelet API via nodes/proxy",
		Description: "nodes/proxy reaches the kubelet API, which allows running commands in any pod on the node and bypasses API server audit logging and admission.",
		Remediation: "Remove nodes/proxy. Monitoring agents should use the /metrics endpoints via nodes/metrics or the metrics API instead.",
	},
	{
		ID: "RS008", Name: "secrets-read", Severity: High,
		Title:       "Subject can read secrets",
		Description: "get/list/watch on secrets exposes credentials, including legacy service account tokens. Note that list and watch return full secret contents. Cluster-wide read is equivalent to obtaining every credential stored in the cluster.",
		Remediation: "Restrict secret access to specific namespaces and, where possible, specific resourceNames with get only.",
	},
	{
		ID: "RS009", Name: "serviceaccount-token-create", Severity: High,
		Title:       "Subject can mint service account tokens",
		Description: "create on serviceaccounts/token issues a bound token for a service account, granting all of its permissions.",
		Remediation: "Remove serviceaccounts/token create or restrict it with resourceNames.",
	},
	{
		ID: "RS010", Name: "csr-approve", Severity: Critical,
		Title:       "Subject can create and approve certificate signing requests",
		Description: "create on certificatesigningrequests plus update on certificatesigningrequests/approval (and approve on the kube-apiserver-client signer) lets the subject mint client certificates for any user or group, including system:masters.",
		Remediation: "Separate CSR creation and approval duties; restrict approve on signers to specific signerNames via resourceNames.",
	},
	{
		ID: "RS011", Name: "admission-webhook-write", Severity: High,
		Title:       "Subject can modify admission webhook configurations",
		Description: "Mutating webhooks can inject containers, service accounts or privileged settings into every pod created in the cluster; validating webhooks receive every admitted object, including secrets, and can deny traffic.",
		Remediation: "Limit webhook configuration writes to the deployment pipeline identity.",
	},
	{
		ID: "RS012", Name: "persistentvolume-create", Severity: High,
		Title:       "Subject can create PersistentVolumes",
		Description: "A PersistentVolume can point at a hostPath on a node; binding it to a claim gives pods access to the node filesystem regardless of Pod Security settings on hostPath volumes.",
		Remediation: "Use dynamic provisioning through StorageClasses and remove create on persistentvolumes.",
	},
	{
		ID: "RS013", Name: "broad-group-binding", Severity: High,
		Title:       "Binding grants permissions to all (un)authenticated users or all service accounts",
		Description: "Subjects system:unauthenticated / system:anonymous apply to anyone who can reach the API server; system:authenticated applies to every identity including every service account in the cluster; system:serviceaccounts applies to every service account.",
		Remediation: "Bind to specific users, groups or service accounts.",
	},
	{
		ID: "RS014", Name: "default-sa-privileged", Severity: Medium,
		Title:       "Namespace default service account has permissions and is automounted",
		Description: "Pods that do not set serviceAccountName run as \"default\". When that service account has RBAC permissions and the token is automounted, every such pod receives them.",
		Remediation: "Create a dedicated service account per workload, remove bindings from \"default\", and set automountServiceAccountToken: false on the default service account.",
	},
	{
		ID: "RS015", Name: "cluster-admin-inventory", Severity: Info,
		Title:       "cluster-admin binding inventory",
		Description: "Inventory of every binding to the cluster-admin ClusterRole (or an equivalent */*/* role), including built-in ones, for review.",
		Remediation: "Review periodically; every entry should be expected and owned.",
	},
	{
		ID: "RS016", Name: "dangling-binding", Severity: Low,
		Title:       "Binding references a role that does not exist",
		Description: "The binding grants nothing today, but whoever later creates a role with that name silently grants it to the binding's subjects.",
		Remediation: "Delete the binding or create the intended role.",
	},
	{
		ID: "RS017", Name: "pod-runs-as-admin-sa", Severity: High,
		Title:       "Workload runs with a cluster-admin-equivalent service account token",
		Description: "The pod mounts a token for a service account that is cluster-admin-equivalent. Compromise of any container in the pod (RCE, SSRF to the token file, exec) is full cluster compromise.",
		Remediation: "Give the workload a least-privilege service account, or disable automountServiceAccountToken if it does not call the API.",
	},
}

// RuleByID returns a rule by ID.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
