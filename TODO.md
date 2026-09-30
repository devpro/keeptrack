# Running IstarCI on KeepTrack

IstarCI runs this repository's CI pipeline locally, in Docker, on every commit, and blocks `git push` when it fails.
It is recommended but optional: the CI is the GitHub Actions pipeline, which IstarCI only runs before a push.
The workflow files are read as written: nothing here is rewritten or annotated for it.
The tool lives in `devpro/istarci`, and its own backlog is `docs/backlog.md` there.

## Setup

Installed once per machine from GitHub Packages, with a `~/.npmrc` token that reads `@devpro` packages:

```bash
npm install --global @devpro/istarci
istarci daemon install
istarci daemon start
task ci:setup
```

`task ci:setup` registers the repository and installs the pre-push hook.
Only commits made afterwards run: the HEAD at registration is not built.
`task ci` shows the runs, `task ci:logs` the output of the last one, and the dashboard is at `http://127.0.0.1:7842`.

`task ci:from-clone` is the fallback for IstarCI development only: it builds the daemon from a clone and runs the last commit once.

## What is configured

`.istarci.yml` sets the following:

Job            | Image
---------------|------------------------------------------------------------------
`git-check`    | `ghcr.io/devpro/debian-node`, from the local reusable workflow
`markup-lint`  | `ghcr.io/devpro/debian-node`, from the reusable workflow in github-workflow-parts
`code-quality` | `ghcr.io/devpro/ubuntu-dotnet`, from the reusable workflow in github-workflow-parts
`image-scan`   | `ghcr.io/devpro/debian-node`, from the reusable workflow in github-workflow-parts

`runner.docker: true` gives the jobs the host Docker socket, which the image scans build with.
Only `actions/*`, `github/*`, `docker/*` and `devpro/github-workflow-parts/*` are allowed.
`pkg.yaml` is excluded, since it publishes.
`.gitlab-ci.yml` is not read, the GitHub workflows winning, and `workflow.provider: gitlab` reads it instead.

The repository sits on `/mnt/c`, which IstarCI polls rather than watches, with nothing to configure.

## Still to do

- [ ] Replace `scripts/mongodb-install.sh`, which the quality job runs to install MongoDB with `sudo apt` and start it with `systemctl`, with a `mongo:8` service declaring `ports: [27017:27017]`.
  A container has no `systemd`, and the service works the same on GitHub and in IstarCI, on `localhost:27017`.
- [ ] Run `code-quality` and `image-scan` through the installed package on a commit changing the application, and record here what passes.
  The Sonar steps fail locally on the `istarci-secret-SONAR_TOKEN` placeholder, a local run holding no credentials.

## Where to report

A pipeline IstarCI reads wrongly belongs in `devpro/istarci`, with the workflow file and the job concerned.
