# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-08

### Added

- Offline loader for Kubernetes YAML/JSON manifests: multi-document YAML,
  `kind: List` / typed `*List` exports, Roles, ClusterRoles (with
  `aggregationRule`), RoleBindings, ClusterRoleBindings, ServiceAccounts,
  Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets,
  ReplicationControllers, Jobs, CronJobs, PodTemplates, Namespaces and
  Secret metadata. File and line are tracked for every object.
- RBAC authorizer model mirroring upstream evaluation semantics: verbs,
  API groups, resources and subresources (`*/sub`), resourceNames,
  nonResourceURLs with `*` suffix, RoleBinding-to-ClusterRole scoping,
  subject matching for users, groups (including `system:authenticated`,
  `system:unauthenticated`, `system:serviceaccounts[:<ns>]`) and service
  accounts (with namespace defaulting), `system:masters` bypass.
- Iterative ClusterRole aggregation via `matchLabels` and
  `matchExpressions` selectors, with per-rule provenance.
- `who-can`, `can`, `audit` (rules RS001-RS017) and `paths` commands.
- Privilege-escalation graph with 11 techniques and BFS shortest paths.
- Output formats: text, JSON, SARIF 2.1.0, Graphviz DOT, Mermaid.
- `--fail-on` severity gate with exit code 3.

[0.1.0]: https://github.com/Opsbreak/rbacscope/releases/tag/v0.1.0
