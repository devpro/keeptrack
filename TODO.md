# Running IstarCI on KeepTrack

IstarCI runs this repository's existing CI pipeline locally, in Docker, on every commit, and blocks `git push` when it fails.
The workflow files are read as written: nothing here has to be rewritten or annotated for it.

This file says what runs today, what does not yet, and what to do about each.
It was written from parsing `.github/workflows/ci.yaml` on 2026-09-13 and reading what it became, so the job names and step counts below are what IstarCI would actually run.

The tool itself lives in `devpro/istarci`, and its own list of what is missing is in `docs/backlog.md` there.

## Quickstart

### Requirements

- Docker, running, and reachable by the current user without `sudo`.
- `bash`, `git`, `curl` and `jq`.
- A clone of IstarCI, since it is not published to the public registry: `git clone https://github.com/devpro/istarci`.
- Node.js 22 or later and pnpm 9 or later, for the daemon only.
  The one-off check below needs none of that: it builds and runs the daemon in a container.
- Network access on the first run of a pipeline.
  Reusable workflows and composite actions are fetched once and kept in `~/.istarci/workflow-cache`, and every run after that reads them from disk.

### Check this repository once, without installing anything

From the IstarCI clone:

```bash
scripts/check_repo.sh /mnt/c/Users/BertrandThomas/Projects/keeptrack --workflow .github/workflows/ci.yaml --image mcr.microsoft.com/dotnet/sdk:10.0
```

The repository is mounted read only.
It is never checked out, never committed to and never written to: the commit under test is extracted into a throwaway workspace instead, so this is safe to run against a working tree with uncommitted changes.

Useful options:

```bash
--workflow .github/workflows/ci.yaml   # one workflow instead of every file discovered
--sha <commit>                         # a commit other than HEAD
--job-image '<pattern>=<image>'        # an image for the jobs a pattern names, repeatable
--timeout 1800                         # longer than the 900 second default, for a pipeline that builds
--keep                                 # leave the daemon container up afterwards, to read its log
```

### Run the daemon, and gate `git push` on the result

From the IstarCI clone:

```bash
pnpm install
pnpm build
node packages/cli/dist/cli.js daemon install
node packages/cli/dist/cli.js daemon start
node packages/cli/dist/cli.js daemon ping
```

Then, for this repository:

```bash
node packages/cli/dist/cli.js add /mnt/c/Users/BertrandThomas/Projects/keeptrack
node packages/cli/dist/cli.js install-hook /mnt/c/Users/BertrandThomas/Projects/keeptrack
```

From then on every commit runs the pipeline in the background, and a push is blocked when the run for the commit being pushed failed.

```bash
node packages/cli/dist/cli.js status      # what ran, and how it ended
node packages/cli/dist/cli.js logs        # the output of the last run
node packages/cli/dist/cli.js check       # the decision the pre-push hook makes
node packages/cli/dist/cli.js list        # the repositories being watched
```

The dashboard is at `http://127.0.0.1:7842`.

## What runs today

Five jobs are read out of `ci.yaml`.
Three of them come from reusable workflows in `devpro/github-workflow-parts`, which IstarCI fetches and inlines, and the real commands live in composite actions inside that repository, which it now fetches and inlines as well.

Job                             | Steps | Needs                                   | State
--------------------------------|-------|-----------------------------------------|---------------------------
`git-check__git-check`          | 3     | `git`, the version out of `Directory.Build.props` | Runs, and its change detection was verified against real commits
`markup-lint__markup-lint`      | 2     | `npx markdownlint-cli2`, `pipx run yamllint` | Runs on an image carrying Node and pipx
`code-quality__dotnet-quality`  | 21    | .NET SDK 10, Java for Sonar, Syft       | Runs on the .NET SDK image, as far as the parts named below
`image-scan__0__container-scan` | 4     | `docker build`, Trivy                   | Blocked, see below
`image-scan__1__container-scan` | 4     | `docker build`, Trivy                   | Blocked, see below

The quality job is the one worth noting: it used to be three steps of setup, because the composite actions holding the work were skipped, and a job that does nothing passes.
It is now the twenty one steps that restore, lint, build, test, report and produce an SBOM.

## What is blocked, and what to do

### The quality job wants more than the .NET SDK

`actions/setup-dotnet` and `actions/setup-java` are skipped, because a setup action assumes a runner image with toolchains preinstalled, which a plain container is not.
The .NET version is already fixed by the image, so `setup-dotnet` costs nothing.
Java is different: the Sonar scanner needs it, and `ghcr.io/devpro/ubuntu-dotnet` carries the .NET SDK with a JRE.

`SONAR_TOKEN` resolves to the placeholder `istarci-secret-SONAR_TOKEN`, which is deliberate: a local run holds no credentials, so the Sonar step fails where it uses it rather than silently analysing nothing.
Disabling Sonar locally is the cleaner answer, and the reusable workflow already takes `sonar-enabled` as an input.

### The image scan jobs want a Docker socket and `${{ env.IMAGE_REF }}`

`docker build . --tag ${{ env.IMAGE_REF }}` needs a Docker client inside the job container, which no job gets today, and the expression reaches the shell unresolved because IstarCI resolves `inputs`, `github`, `matrix`, `secrets` and `vars` and not `env`.
Both are IstarCI gaps, items 1 and 3 of its backlog, and neither needs a change here.

### The code has lint findings

On these images, `markup-lint` and `code-quality` run to the end of their tooling and fail on the code itself: 148 markdownlint issues, mostly `MD013` line length under `docs/findings`, and `dotnet format` whitespace and import ordering in `test/BlazorApp.PlaywrightTests` and `src/WebApi/ReferenceData`.

### The GitLab pipeline is not reachable by default

This repository carries both `.gitlab-ci.yml` and `.github/workflows`, and GitHub wins wherever there are workflows.
Reading the GitLab one instead needs `workflow.provider: gitlab`, shown below.
Its `workflow:` rules admit only the default branch, so a commit on any other branch is correctly recorded as no pipeline at all.

## Suggested `.istarci.yml`

```yaml
runner:
  image: ghcr.io/devpro/ubuntu-dotnet:latest
  images:
    "markup-lint*": ghcr.io/devpro/debian-node:latest
    "git-check*": ghcr.io/devpro/debian-node:latest

workflow:
  exclude:
    - .github/workflows/pkg.yaml   # publishes on a push to main, so it should not run locally
  # provider: gitlab               # uncomment to read .gitlab-ci.yml instead of the workflows
```

### This repository sits on a Windows drive

`/mnt/c` is a Windows filesystem mounted into WSL, which delivers no inotify event, so the watcher polls it rather than waiting for one.
That is selected automatically for a `/mnt/<letter>` path and needs no configuration.
Cloning a workspace across that boundary cannot use hard links, which IstarCI also detects, so a run is a little slower there than on a repository under the Linux home.

Running the pipeline from the WSL side is what was verified, including bind mounting the Windows path into a container and extracting a commit from it.

## Where to report

A fault in the pipeline as IstarCI reads it belongs in `devpro/istarci`, with the workflow file and the job that was read wrongly.
`docs/backlog.md` there already records the gaps named above, so an issue is worth opening for anything not on that list.
