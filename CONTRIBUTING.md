# Contributing to rbacscope

Thanks for helping improve rbacscope. Bug reports, new audit rules, new
escalation techniques and semantics fixes are all welcome.

## Ground rules

- Security issues: follow [SECURITY.md](SECURITY.md), not public issues.
- Never attach real cluster exports to issues or pull requests. Reduce the
  problem to a few synthetic manifests.
- Keep dependencies minimal. rbacscope intentionally does not depend on
  client-go or apimachinery; the only runtime dependency is `gopkg.in/yaml.v3`.

## Development

Requirements: Go 1.22 or newer.

```sh
go build ./cmd/rbacscope
go test ./...
go test -race ./...
go vet ./...
gofmt -l .            # must print nothing
go test ./internal/synth -run '^$' -bench . -benchmem   # benchmarks
```

### Golden files

CLI output for the fixture cluster in `testdata/cluster/` is pinned by golden
files in `testdata/golden/`. If you intentionally change output:

```sh
go test ./cmd/rbacscope -update
git diff testdata/golden   # review every change
```

## Changing authorization semantics

`internal/rbac` mirrors the upstream RBAC authorizer
(`pkg/apis/rbac/v1/evaluation_helpers.go` and
`plugin/pkg/auth/authorizer/rbac`). Any change there must:

1. cite the upstream behaviour it models (link or Kubernetes docs section), and
2. add table-driven cases to `internal/rbac/*_test.go` covering both the
   allowed and the denied side.

## Adding an audit rule

1. Append the rule to `internal/audit/rules.go` with the next free `RSnnn` ID
   (IDs are never reused or renumbered).
2. Implement it in `internal/audit/audit.go`.
3. Add at least one positive and one negative case to `TestRules` in
   `internal/audit/audit_test.go`.
4. Document it in the README rule table, with remediation.

## Adding an escalation technique

1. Add a `Technique` constant and description in `internal/paths/paths.go`.
2. Emit edges in `edgesFor`, attaching evidence (binding -> role) and setting
   `Approximate` if the edge depends on information not visible offline.
3. Add positive and negative cases to `TestPaths`.
4. Document it in the README.

## Pull requests

- One logical change per PR; include tests.
- Update `CHANGELOG.md` under an "Unreleased" heading.
- CI (tests on Linux/macOS/Windows, race detector, vet, gofmt, cross-build)
  must pass.
