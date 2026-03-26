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

Runs on pull requests targeting `main` only. CI is not re-run on push to `main` — the code was already tested on the PR branch before merging. All five jobs must pass for a PR to be mergeable.

| Job | Description |
|---|---|
| **Check** | `cargo check --all-targets` — verifies the code compiles |
| **Test** | `cargo test --all` — runs the full test suite |
| **Clippy** | `cargo clippy --all-targets -- -D warnings` — lint checks with warnings as errors |
| **Formatting** | `cargo fmt --all -- --check` — verifies code is formatted |
| **PR Title** | Validates the PR title follows conventional commits format (PR-only) |

The Check/Test/Clippy/Formatting jobs are skipped automatically when no Rust files (`.rs`, `Cargo.toml`, `Cargo.lock`) are changed, saving runner minutes on docs-only or CI-only PRs.

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
| `docs:` | **none** (no release) | `docs: update server setup guide` |
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
    and dispatches release.yml via workflow_dispatch
          |
          v
    release.yml builds cross-compiled binaries:
      - x86_64-linux-gnu
      - aarch64-linux-gnu
      - x86_64-apple-darwin
      - aarch64-apple-darwin
      - x86_64-windows-msvc
          |
          v
    Creates GitHub Release with binaries
```

## Release Workflow

**File:** `.github/workflows/release.yml`

Triggered either by a `v*` tag push or dispatched by `tag-release.yml` after creating a tag. Builds release binaries for all supported platforms, packages them as tarballs, then creates a GitHub Release with auto-generated release notes.

### Build Targets

| Target Triple | Artifact Name | OS | Binary |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `x86_64-linux-gnu` | Linux x86_64 | `rgrok`, `rgrok-server` |
| `aarch64-unknown-linux-gnu` | `aarch64-linux-gnu` | Linux ARM64 | `rgrok`, `rgrok-server` |
| `x86_64-apple-darwin` | `x86_64-apple-darwin` | macOS Intel | `rgrok`, `rgrok-server` |
| `aarch64-apple-darwin` | `aarch64-apple-darwin` | macOS Apple Silicon | `rgrok`, `rgrok-server` |
| `x86_64-pc-windows-msvc` | `x86_64-windows-msvc` | Windows x86_64 | `rgrok.exe`, `rgrok-server.exe` |

Artifact filenames use a clean name (without the Rust vendor field) — e.g. `rgrok-x86_64-linux-gnu.tar.gz` rather than `rgrok-x86_64-unknown-linux-gnu.tar.gz`.

## Notes

- The PR title validation job only runs on pull requests, not direct pushes
- Squash merge is enforced at the repo level — merge commits and rebase merges are disabled
- `docs:`, `chore:`, `ci:`, `test:`, and `build:` PRs produce no tag and no release
- The tagging workflow has loop protection: `tag-release.yml` only triggers on branch pushes (not tag pushes), so creating a tag does not re-trigger itself
