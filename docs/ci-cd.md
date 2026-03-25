# CI/CD and Semantic Versioning

This document describes the CI/CD pipelines, branch protection rules, and automatic semantic versioning used in this project.

## Branch Protection

The `main` branch is protected with the following rules:

- **No direct pushes** — all changes must go through a pull request
- **Squash merge only** — the PR title becomes the commit message on `main`
- **Required approvals** — at least 1 approving review from the repo owner
- **Required status checks** — all CI jobs must pass before merging
- **Force pushes and deletions are blocked**
- **Stale reviews are dismissed** when new commits are pushed

## CI Workflow

**File:** `.github/workflows/ci.yml`

Runs on every push to `main` and on every pull request targeting `main`. All five jobs must pass for a PR to be mergeable.

| Job | Description |
|---|---|
| **Check** | `cargo check --all-targets` — verifies the code compiles |
| **Test** | `cargo test --all` — runs the full test suite |
| **Clippy** | `cargo clippy --all-targets -- -D warnings` — lint checks with warnings as errors |
| **Formatting** | `cargo fmt --all -- --check` — verifies code is formatted |
| **PR Title** | Validates the PR title follows conventional commits format (PR-only) |

## Semantic Versioning

Version tags are created automatically when a PR is merged to `main`. The version bump is determined by the PR title prefix, following the [Conventional Commits](https://www.conventionalcommits.org/) specification.

**File:** `.github/workflows/tag-release.yml`

Uses [`mathieudutour/github-tag-action`](https://github.com/mathieudutour/github-tag-action) to parse the squash-merge commit message (which is the PR title) and create a semver tag.

### PR Title Format

```
<type>[optional scope][!]: <description>
```

### Version Bump Rules

| PR Title Prefix | Semver Bump | Example |
|---|---|---|
| `feat:` | **minor** (0.x.0) | `feat: add TCP health-check probes` |
| `feat!:` | **major** (x.0.0) | `feat!: redesign protocol framing` |
| `fix:` | patch (0.0.x) | `fix: resolve yamux stream leak` |
| `perf:` | patch | `perf: reduce allocations in proxy loop` |
| `refactor:` | patch | `refactor: extract tunnel state machine` |
| `docs:` | patch | `docs: update server setup guide` |
| `chore:` | **none** (no release) | `chore: update dependencies` |
| `ci:` | **none** (no release) | `ci: pin actions to SHA` |
| `test:` | **none** (no release) | `test: add integration tests for auth` |
| `build:` | **none** (no release) | `build: update Dockerfile base image` |

The `!` suffix on any type signals a breaking change and triggers a **major** bump.

### Pipeline Flow

```
PR opened with conventional commit title
          |
          v
    CI runs all 5 checks
          |
          v
    Owner approves + merges (squash)
          |
          v
    tag-release.yml parses commit message
          |
          v
    Creates version tag (e.g. v0.2.0)
          |
          v
    release.yml triggers on v* tag
          |
          v
    Builds cross-compiled binaries:
      - x86_64-unknown-linux-gnu
      - x86_64-apple-darwin
      - aarch64-apple-darwin
      - x86_64-pc-windows-msvc
          |
          v
    Creates GitHub Release with binaries
```

## Release Workflow

**File:** `.github/workflows/release.yml`

Triggered by any `v*` tag push. Builds release binaries for all supported platforms, packages them as `rgrok-<target>` and `rgrok-server-<target>`, then creates a GitHub Release with auto-generated release notes.

### Build Targets

| Target | OS | Binary |
|---|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 | `rgrok`, `rgrok-server` |
| `x86_64-apple-darwin` | macOS Intel | `rgrok`, `rgrok-server` |
| `aarch64-apple-darwin` | macOS Apple Silicon | `rgrok`, `rgrok-server` |
| `x86_64-pc-windows-msvc` | Windows x86_64 | `rgrok.exe`, `rgrok-server.exe` |

## Notes

- The PR title validation job only runs on pull requests, not direct pushes
- Squash merge is enforced at the repo level — merge commits and rebase merges are disabled
- The tagging workflow has loop protection: tag pushes trigger `release.yml` (tags filter), not `tag-release.yml` (branches filter)
- `chore:`, `ci:`, `test:`, and `build:` PRs produce no tag and no release
