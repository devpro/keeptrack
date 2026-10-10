# CI and code quality

The pipelines, the local CI runner, and the static analysis findings that are settled.

## Pipelines

GitHub Actions (`.github/workflows/ci.yaml`) runs on push and pull request to `main`:

- a git and markup lint job;
- a .NET quality job (build, test with coverage, SonarCloud, FOSSA), gated on application changes;
- a container image scan for both Dockerfiles.

`pkg.yaml` publishes the container images.
Equivalent pipelines exist for GitLab CI (`.gitlab-ci.yml`) and Azure DevOps.

Only actions published by `github` or `docker` are used, plus the reusable workflows of `devpro/github-workflow-parts`.
Anything else is an explicit command downloading the official release binary and checking its SHA256 checksum.

Coverage is sent to SonarCloud, and no threshold fails the build.

## IstarCI

[IstarCI](https://github.com/devpro/istarci) runs the GitHub Actions pipeline locally, in containers, on every commit, and blocks `git push` when it failed.
It is optional, since the CI is the GitHub Actions pipeline, and it reads the workflow files as written, with nothing rewritten for it.
Setup is in [CONTRIBUTING.md](../CONTRIBUTING.md#continuous-integration).

`.istarci.yml` sets the image of each job:

Job            | Image                          | Workflow
---------------|--------------------------------|----------------------------
`git-check`    | `ghcr.io/devpro/debian-node`   | The local reusable workflow
`markup-lint`  | `ghcr.io/devpro/debian-node`   | `github-workflow-parts`
`code-quality` | `ghcr.io/devpro/ubuntu-dotnet` | `github-workflow-parts`
`image-scan`   | `ghcr.io/devpro/debian-node`   | `github-workflow-parts`

- `runner.docker: true` gives the jobs the host Docker socket, which the image scans build with.
- `pkg.yaml` is excluded, since it publishes.
- `.gitlab-ci.yml` is not read, the GitHub workflows taking precedence, unless `workflow.provider: gitlab` is set.
- The repository sits on `/mnt/c`, which IstarCI polls rather than watches, with nothing to configure.
- The Sonar steps fail locally on the `istarci-secret-SONAR_TOKEN` placeholder, since a local run holds no credentials.

A pipeline IstarCI reads wrongly is reported in `devpro/istarci`, with the workflow file and the job concerned.

## Sonar

### S8970 in Razor is a false positive

Sonar loses the nullable context in Razor-generated code, so it reports every `!` in markup as useless.
`BlazorApp` has nullable enabled project-wide and each `!` suppresses a real nullable API (`ClaimsPrincipal.Identity`, `ChangeEventArgs.Value`), so removing one brings back `CS8600`/`CS8602`.
They are resolved in bulk as False Positive in SonarCloud rather than edited.

### S8969 is checked case by case

It looks like S8970 but applies to plain `.cs` files, and it can be real.
The `!` in `TvTimeImportService.cs` stays: removing it reintroduces `CS8601`, since `[MaybeNullWhen(false)]` does not flow through the open generic `TModel`.

### S107 on the import merge

The import engine takes one `OwnedItemImportAdapter<TModel, TRequestItem>` rather than six separate delegates, which keeps its generic-engine-over-delegates design within the parameter count.

### ASP0025

Both `Program.cs` files register policies with `AddAuthorizationBuilder().AddPolicy(...)`, and the `AdminOnly`/`MemberOnly` resource tests prove the policies are still enforced.
