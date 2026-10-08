// Package loader reads Kubernetes manifests (multi-document YAML, JSON, and
// kind: List exports) into the minimal rbacscope object model, recording the
// file and line each object was defined at.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Opsbreak/rbacscope/internal/model"
)

// LoadPaths loads every .yaml/.yml/.json file found in the given files or
// directories (directories are walked recursively, in lexical order).
func LoadPaths(paths []string) (*model.Cluster, error) {
	l := newLoader()
	for _, p := range paths {
		if p == "-" {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, fmt.Errorf("reading stdin: %w", err)
			}
			if err := l.loadBytes("<stdin>", data); err != nil {
				return nil, err
			}
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			if err := l.loadFile(p); err != nil {
				return nil, err
			}
			continue
		}
		var files []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != p && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml", ".json":
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
		for _, f := range files {
			if err := l.loadFile(f); err != nil {
				return nil, err
			}
		}
	}
	return l.finish(), nil
}

// LoadBytes parses a single in-memory manifest stream. name is used as the
// source file name in findings.
func LoadBytes(name string, data []byte) (*model.Cluster, error) {
	l := newLoader()
	if err := l.loadBytes(name, data); err != nil {
		return nil, err
	}
	return l.finish(), nil
}

type loader struct {
	c    *model.Cluster
	seen map[string]int // object key -> index marker for duplicate detection
}

func newLoader() *loader {
	return &loader{
		c:    &model.Cluster{Skipped: map[string]int{}},
		seen: map[string]int{},
	}
}

func (l *loader) loadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return l.loadBytes(filepath.ToSlash(filepath.Clean(path)), data)
}

func (l *loader) loadBytes(name string, data []byte) error {
	// Strip a UTF-8 BOM, which PowerShell's Out-File likes to add.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
			continue
		}
		if err := l.handle(name, doc.Content[0]); err != nil {
			return err
		}
	}
}

// field returns the value node for key in a mapping node.
func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node, key string) string {
	v := field(n, key)
	if v == nil || v.Kind != yaml.ScalarNode {
		return ""
	}
	return v.Value
}

type podSpec struct {
	ServiceAccountName           string      `yaml:"serviceAccountName"`
	DeprecatedServiceAccount     string      `yaml:"serviceAccount"`
	AutomountServiceAccountToken *bool       `yaml:"automountServiceAccountToken"`
	NodeName                     string      `yaml:"nodeName"`
	Containers                   []container `yaml:"containers"`
	InitContainers               []container `yaml:"initContainers"`
	Volumes                      []volume    `yaml:"volumes"`
}

type container struct {
	SecurityContext *struct {
		Privileged *bool `yaml:"privileged"`
	} `yaml:"securityContext"`
}

type volume struct {
	HostPath *struct {
		Path string `yaml:"path"`
	} `yaml:"hostPath"`
}

type podTemplate struct {
	Metadata model.ObjectMeta `yaml:"metadata"`
	Spec     podSpec          `yaml:"spec"`
}

func (l *loader) handle(file string, n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	kind := scalar(n, "kind")
	src := model.Source{File: file, Line: n.Line}
	if strings.HasSuffix(kind, "List") {
		items := field(n, "items")
		if items == nil || items.Kind != yaml.SequenceNode {
			return nil
		}
		for _, it := range items.Content {
			if err := l.handle(file, it); err != nil {
				return err
			}
		}
		return nil
	}
	decode := func(v interface{}) error {
		if err := n.Decode(v); err != nil {
			return fmt.Errorf("%s:%d: decoding %s: %w", file, n.Line, kind, err)
		}
		return nil
	}
	switch kind {
	case model.KindRole, model.KindClusterRole:
		var raw struct {
			Metadata        model.ObjectMeta       `yaml:"metadata"`
			Rules           []model.PolicyRule     `yaml:"rules"`
			AggregationRule *model.AggregationRule `yaml:"aggregationRule"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		r := &model.Role{Kind: kind, Meta: raw.Metadata, Rules: raw.Rules, AggregationRule: raw.AggregationRule, Source: src}
		if kind == model.KindRole {
			defaultNS(&r.Meta)
			if l.dedupe(kind, r.Meta, src) {
				l.c.Roles = replaceRole(l.c.Roles, r)
			} else {
				l.c.Roles = append(l.c.Roles, r)
			}
		} else {
			r.Meta.Namespace = ""
			if r.AggregationRule != nil && r.Meta.Name != "" && len(r.AggregationRule.ClusterRoleSelectors) == 0 {
				r.AggregationRule = nil
			}
			if l.dedupe(kind, r.Meta, src) {
				l.c.ClusterRoles = replaceRole(l.c.ClusterRoles, r)
			} else {
				l.c.ClusterRoles = append(l.c.ClusterRoles, r)
			}
		}
	case model.KindRoleBinding, model.KindClusterRoleBinding:
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
			RoleRef  model.RoleRef    `yaml:"roleRef"`
			Subjects []model.Subject  `yaml:"subjects"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		b := &model.Binding{Kind: kind, Meta: raw.Metadata, RoleRef: raw.RoleRef, Subjects: raw.Subjects, Source: src}
		if kind == model.KindRoleBinding {
			defaultNS(&b.Meta)
		} else {
			b.Meta.Namespace = ""
		}
		for i := range b.Subjects {
			s := &b.Subjects[i]
			if s.Kind != model.SubjectServiceAccount || s.Namespace != "" {
				continue
			}
			// Mirrors the RBAC authorizer: an SA subject without a namespace
			// in a RoleBinding defaults to the binding's namespace.
			if kind == model.KindRoleBinding {
				s.Namespace = b.Meta.Namespace
			} else {
				l.c.Warnings = append(l.c.Warnings, fmt.Sprintf("%s: %s has ServiceAccount subject %q without namespace; it can never match", src, b.Ref(), s.Name))
			}
		}
		if kind == model.KindRoleBinding && b.RoleRef.Kind != model.KindRole && b.RoleRef.Kind != model.KindClusterRole {
			l.c.Warnings = append(l.c.Warnings, fmt.Sprintf("%s: %s has unsupported roleRef kind %q", src, b.Ref(), b.RoleRef.Kind))
		}
		if kind == model.KindClusterRoleBinding && b.RoleRef.Kind != model.KindClusterRole {
			l.c.Warnings = append(l.c.Warnings, fmt.Sprintf("%s: %s references %s %q; ClusterRoleBindings can only reference ClusterRoles", src, b.Ref(), b.RoleRef.Kind, b.RoleRef.Name))
		}
		if l.dedupe(kind, b.Meta, src) {
			if kind == model.KindRoleBinding {
				l.c.RoleBindings = replaceBinding(l.c.RoleBindings, b)
			} else {
				l.c.ClusterRoleBindings = replaceBinding(l.c.ClusterRoleBindings, b)
			}
		} else if kind == model.KindRoleBinding {
			l.c.RoleBindings = append(l.c.RoleBindings, b)
		} else {
			l.c.ClusterRoleBindings = append(l.c.ClusterRoleBindings, b)
		}
	case "ServiceAccount":
		var raw struct {
			Metadata                     model.ObjectMeta `yaml:"metadata"`
			AutomountServiceAccountToken *bool            `yaml:"automountServiceAccountToken"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		sa := &model.ServiceAccount{Meta: raw.Metadata, AutomountServiceAccountToken: raw.AutomountServiceAccountToken, Source: src}
		if l.dedupe(kind, sa.Meta, src) {
			for i, o := range l.c.ServiceAccounts {
				if o.Meta.Namespace == sa.Meta.Namespace && o.Meta.Name == sa.Meta.Name {
					l.c.ServiceAccounts[i] = sa
				}
			}
		} else {
			l.c.ServiceAccounts = append(l.c.ServiceAccounts, sa)
		}
	case "Pod":
		var raw podTemplate
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		l.c.Pods = append(l.c.Pods, toPod(raw.Metadata, raw.Spec, "", "", src))
	case "PodTemplate":
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
			Template podTemplate      `yaml:"template"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		l.c.Pods = append(l.c.Pods, toPod(raw.Metadata, raw.Template.Spec, kind, raw.Metadata.Name, src))
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
			Spec     struct {
				Template podTemplate `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		l.c.Pods = append(l.c.Pods, toPod(raw.Metadata, raw.Spec.Template.Spec, kind, raw.Metadata.Name, src))
	case "CronJob":
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
			Spec     struct {
				JobTemplate struct {
					Spec struct {
						Template podTemplate `yaml:"template"`
					} `yaml:"spec"`
				} `yaml:"jobTemplate"`
			} `yaml:"spec"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		l.c.Pods = append(l.c.Pods, toPod(raw.Metadata, raw.Spec.JobTemplate.Spec.Template.Spec, kind, raw.Metadata.Name, src))
	case "Secret":
		// Only metadata and type are decoded. data/stringData are never read
		// into memory structures.
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
			Type     string           `yaml:"type"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		defaultNS(&raw.Metadata)
		l.c.Secrets = append(l.c.Secrets, &model.Secret{Meta: raw.Metadata, Type: raw.Type, Source: src})
	case "Namespace":
		var raw struct {
			Metadata model.ObjectMeta `yaml:"metadata"`
		}
		if err := decode(&raw); err != nil {
			return err
		}
		raw.Metadata.Namespace = ""
		if !l.dedupe(kind, raw.Metadata, src) {
			l.c.Namespaces = append(l.c.Namespaces, &model.Namespace{Meta: raw.Metadata, Source: src})
		}
	case "":
		// Not a Kubernetes object (e.g. a kustomization or values file).
	default:
		l.c.Skipped[kind]++
	}
	return nil
}

// dedupe reports whether an object with the same identity was seen before
// (in which case the caller replaces it: last definition wins, like apply).
func (l *loader) dedupe(kind string, m model.ObjectMeta, src model.Source) bool {
	key := kind + "/" + m.Namespace + "/" + m.Name
	if _, ok := l.seen[key]; ok {
		l.c.Warnings = append(l.c.Warnings, fmt.Sprintf("%s: duplicate %s %q; the later definition wins", src, kind, strings.TrimPrefix(m.Namespace+"/"+m.Name, "/")))
		return true
	}
	l.seen[key] = 1
	return false
}

func replaceRole(list []*model.Role, r *model.Role) []*model.Role {
	for i, o := range list {
		if o.Meta.Namespace == r.Meta.Namespace && o.Meta.Name == r.Meta.Name {
			list[i] = r
		}
	}
	return list
}

func replaceBinding(list []*model.Binding, b *model.Binding) []*model.Binding {
	for i, o := range list {
		if o.Meta.Namespace == b.Meta.Namespace && o.Meta.Name == b.Meta.Name {
			list[i] = b
		}
	}
	return list
}

func defaultNS(m *model.ObjectMeta) {
	if m.Namespace == "" {
		m.Namespace = "default"
	}
}

func toPod(meta model.ObjectMeta, spec podSpec, ownerKind, ownerName string, src model.Source) *model.Pod {
	sa := spec.ServiceAccountName
	if sa == "" {
		sa = spec.DeprecatedServiceAccount
	}
	if sa == "" {
		sa = "default"
	}
	p := &model.Pod{
		Meta:                         meta,
		ServiceAccountName:           sa,
		AutomountServiceAccountToken: spec.AutomountServiceAccountToken,
		NodeName:                     spec.NodeName,
		OwnerKind:                    ownerKind,
		OwnerName:                    ownerName,
		Source:                       src,
	}
	for _, c := range append(append([]container{}, spec.Containers...), spec.InitContainers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			p.Privileged = true
		}
	}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			p.HostPath = true
		}
	}
	return p
}

func (l *loader) finish() *model.Cluster {
	return l.c
}
