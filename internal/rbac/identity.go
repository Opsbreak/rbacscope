package rbac

import (
	"fmt"
	"strings"

	"github.com/Opsbreak/rbacscope/internal/model"
)

// Well-known groups.
const (
	GroupAuthenticated   = "system:authenticated"
	GroupUnauthenticated = "system:unauthenticated"
	GroupServiceAccounts = "system:serviceaccounts"
	GroupMasters         = "system:masters"
	SAUserPrefix         = "system:serviceaccount:"
	SAGroupPrefix        = "system:serviceaccounts:"
)

// Identity is a principal: a User, a Group, or a ServiceAccount.
type Identity struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	// ExtraGroups are additional groups the caller asserts the identity is a
	// member of (group membership is not visible in RBAC objects).
	ExtraGroups []string `json:"extraGroups,omitempty"`
}

// UserID, GroupID and SAID are convenience constructors.
func UserID(name string) Identity { return identityFromUsername(name) }

// GroupID returns a Group identity.
func GroupID(name string) Identity { return Identity{Kind: model.SubjectGroup, Name: name} }

// SAID returns a ServiceAccount identity.
func SAID(ns, name string) Identity {
	return Identity{Kind: model.SubjectServiceAccount, Namespace: ns, Name: name}
}

func identityFromUsername(name string) Identity {
	if strings.HasPrefix(name, SAUserPrefix) {
		parts := strings.SplitN(strings.TrimPrefix(name, SAUserPrefix), ":", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			return SAID(parts[0], parts[1])
		}
	}
	return Identity{Kind: model.SubjectUser, Name: name}
}

// ParseIdentity parses the CLI subject syntax:
//
//	alice | user:alice                         a User
//	group:dev                                  a Group
//	sa:ns/name | serviceaccount:ns/name        a ServiceAccount
//	system:serviceaccount:ns:name              a ServiceAccount (username form)
func ParseIdentity(s string) (Identity, error) {
	s = strings.TrimSpace(s)
	lower := strings.ToLower(s)
	switch {
	case s == "":
		return Identity{}, fmt.Errorf("empty subject")
	case strings.HasPrefix(lower, "group:"):
		n := s[len("group:"):]
		if n == "" {
			return Identity{}, fmt.Errorf("empty group name in %q", s)
		}
		return GroupID(n), nil
	case strings.HasPrefix(lower, "sa:"), strings.HasPrefix(lower, "serviceaccount:"):
		rest := s[strings.Index(s, ":")+1:]
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return Identity{}, fmt.Errorf("service account must be written sa:NAMESPACE/NAME, got %q", s)
		}
		return SAID(parts[0], parts[1]), nil
	case strings.HasPrefix(lower, "user:"):
		n := s[len("user:"):]
		if n == "" {
			return Identity{}, fmt.Errorf("empty user name in %q", s)
		}
		return identityFromUsername(n), nil
	}
	return identityFromUsername(s), nil
}

// IdentityFromSubject converts a binding subject to an Identity. User
// subjects named system:serviceaccount:ns:name are normalised to SAs.
func IdentityFromSubject(s model.Subject) Identity {
	switch s.Kind {
	case model.SubjectServiceAccount:
		return SAID(s.Namespace, s.Name)
	case model.SubjectGroup:
		return GroupID(s.Name)
	}
	return identityFromUsername(s.Name)
}

// String renders the identity in CLI syntax (round-trips with ParseIdentity).
func (i Identity) String() string {
	switch i.Kind {
	case model.SubjectServiceAccount:
		return "sa:" + i.Namespace + "/" + i.Name
	case model.SubjectGroup:
		return "group:" + i.Name
	}
	return "user:" + i.Name
}

// Key is a stable map key (ignores ExtraGroups).
func (i Identity) Key() string { return i.String() }

// Username is the authenticated user name; Groups have none.
func (i Identity) Username() string {
	switch i.Kind {
	case model.SubjectServiceAccount:
		return SAUserPrefix + i.Namespace + ":" + i.Name
	case model.SubjectUser:
		return i.Name
	}
	return ""
}

// Groups returns the groups a request by this identity carries. A Group
// identity represents "an arbitrary member of the group": it carries the
// group itself plus system:authenticated (unless it is the unauthenticated
// group). Users are assumed authenticated.
func (i Identity) Groups() []string {
	var gs []string
	switch i.Kind {
	case model.SubjectServiceAccount:
		gs = []string{GroupServiceAccounts, SAGroupPrefix + i.Namespace, GroupAuthenticated}
	case model.SubjectGroup:
		switch i.Name {
		case GroupUnauthenticated:
			gs = []string{GroupUnauthenticated}
		case GroupAuthenticated:
			gs = []string{GroupAuthenticated}
		default:
			gs = []string{i.Name, GroupAuthenticated}
		}
	default:
		if i.Name == "system:anonymous" {
			gs = []string{GroupUnauthenticated}
		} else {
			gs = []string{GroupAuthenticated}
		}
	}
	for _, g := range i.ExtraGroups {
		if !contains(gs, g) {
			gs = append(gs, g)
		}
	}
	return gs
}

// subjectKeys returns all binding-subject index keys that match this identity.
func (i Identity) subjectKeys() []string {
	var keys []string
	if u := i.Username(); u != "" {
		keys = append(keys, "User:"+u)
	}
	if i.Kind == model.SubjectServiceAccount {
		keys = append(keys, "ServiceAccount:"+i.Namespace+"/"+i.Name)
	}
	for _, g := range i.Groups() {
		keys = append(keys, "Group:"+g)
	}
	return keys
}

// subjectKey returns the index key of a binding subject.
func subjectKey(s model.Subject) string {
	switch s.Kind {
	case model.SubjectServiceAccount:
		return "ServiceAccount:" + s.Namespace + "/" + s.Name
	case model.SubjectGroup:
		return "Group:" + s.Name
	case model.SubjectUser:
		return "User:" + s.Name
	}
	return s.Kind + ":" + s.Name
}

// IsSystem reports whether the identity is a Kubernetes system principal
// (system:* users and groups, and service accounts in kube-system).
func (i Identity) IsSystem() bool {
	switch i.Kind {
	case model.SubjectServiceAccount:
		return i.Namespace == "kube-system"
	default:
		return strings.HasPrefix(i.Name, "system:")
	}
}
