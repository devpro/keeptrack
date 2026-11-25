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

Job            | Image                                     | Workflow
---------------|-------------------------------------------|----------------------------
`git-check`    | `ghcr.io/devpro/ubuntu-node`              | The local reusable workflow
`markup-lint`  | `ghcr.io/devpro/ubuntu-node`              | `github-workflow-parts`
`code-quality` | `ghcr.io/devpro/ubuntu-dotnet-playwright` | `github-workflow-parts`
`image-scan`   | `ghcr.io/devpro/ubuntu-node`              | `github-workflow-parts`

- `runner.docker: true` gives the jobs the host Docker socket, which the image scans build with.
- `pkg.yaml` is excluded, since it publishes.
- `.gitlab-ci.yml` is not read, the GitHub workflows taking precedence, unless `workflow.provider: gitlab` is set.
- The repository sits on `/mnt/c`, which IstarCI polls rather than watches, with nothing to configure.
- The Sonar analysis runs against the SonarQube of the machine, and its quality gate fails the job.

### No secret reaches a local run

IstarCI holds no credential by design, and nothing works around it: no key in `.istarci.yml`, in the machine's `config.yml`, in an image or in a mounted file.
What a local run adds over GitHub is heavy testing against services started in the job, with values generated for the run.
A test that cannot use a stand-in skips.

### Every suite runs locally

`env:` in `.istarci.yml` turns the integration and end-to-end suites on, for the local runs only.
The GitHub pipeline sets none of these variables, so it runs what it did.

- `E2E_ENABLED`: the end-to-end suite, which also makes `ci.yaml` run `scripts/prepare_e2e.sh` for the indexes and the browser.
- `TEST_AUTHENTICATION_MODE=local`: the Firebase secrets are placeholders.

The tests whose subject is a live provider skip, `TEST_LIVE_PROVIDERS` being `false` under `vars:`, where `ci.yaml` defaults it to `true`.
The job gets a clone of the commit, so neither `Local.runsettings` nor `appsettings.Development.json`, both gitignored, is in it.

A pipeline IstarCI reads wrongly is reported in `devpro/istarci`, with the workflow file and the job concerned.

## Sonar

### Settings are versioned in `SonarQube.Analysis.xml`

The analysis runs the scanner for .NET, which never reads a `sonar-project.properties`.
Settings such as issue exclusions go in the root `SonarQube.Analysis.xml`, which `ci.yaml` passes through the `sonar-settings-file` input.
A setting `ci.yaml` also passes on the command line, such as `sonar-exclusions`, wins over the file.
Which rules are active is the quality profile's, on the server.

**SonarCloud ships a new rule before the SonarQube release IstarCI starts**, so a local analysis can stay quiet about an issue SonarCloud reports.

### S8970 in Razor is a false positive

Sonar loses the nullable context in Razor-generated code, so it reports every `!` in markup as useless.
`BlazorApp` has nullable enabled project-wide and each `!` suppresses a real nullable API (`ClaimsPrincipal.Identity`, `ChangeEventArgs.Value`), so removing one brings back `CS8600`/`CS8602`.
`SonarQube.Analysis.xml` excludes the rule for `*.razor` files.

### S8969 is checked case by case

It looks like S8970 but applies to plain `.cs` files, and it can be real.
The `!` in `TvTimeImportService.cs` stays: removing it reintroduces `CS8601`, since `[MaybeNullWhen(false)]` does not flow through the open generic `TModel`.

### An accepted finding is suppressed where it is

A C# finding accepted by design is suppressed on its own line or member, with the reason beside it, and a JavaScript one with `NOSONAR`.
No file leaves the analysis or the coverage, and no rule is turned off, so the same finding elsewhere is still reported.

### S107

The imports group their parameters: `OwnedItemImportAdapter`, `OwnedItemRepositorySet`, `ReferenceRepositorySet`, and `CollectionImport` in `ReferenceDataImportService`.
Constructors taking their dependencies, and methods whose delegates are the only difference between two domains, keep theirs.

### S5693 on the upload pages

Each page passes an explicit limit to `OpenReadStream`, above Sonar's 8 MB default, and each API endpoint enforces its own on the request.
Neither `SuppressMessage` nor a pragma has an effect in a `.razor` file, so `SonarQube.Analysis.xml` names the five pages.

### Informational findings left open

- `CA1873`: the arguments are property reads and small joins on paths that run once per provider call or per pass.
- `xUnit1033`: the three other factories derive from the fixture their base class declares, and the test class consumes the derived one.

### ASP0025

Both `Program.cs` files register policies with `AddAuthorizationBuilder().AddPolicy(...)`, and the `AdminOnly`/`MemberOnly` resource tests prove the policies are still enforced.
