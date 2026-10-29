# Labs

Interactive labs written for [sidelab](https://github.com/devpro/sidelab).

Lab                                     | Covers
----------------------------------------|----------------------------------------------------------------------------------------------------
[run-from-sources](run-from-sources/)   | Clone, build and run Keeptrack with a local MongoDB and local authentication, then a guided tour

## Shape of a lab

A lab is a directory of numbered steps, each holding an `index.md` and an optional `step.yaml`, with `lab.yaml` at the root carrying the title, the versions and the credentials the lab needs.
A fenced block marked ` ```bash exec ` renders a **Run** button, and `automation.yaml` declares what the lab browser does, with the selectors of the end-to-end page objects.

`run-from-sources` clones the branch named by `KEEPTRACK_BRANCH` in `lab.yaml`, which a tenant or an account can replace under **Environment** in the launcher to try another branch.
The reference data provider keys are optional secrets, set the same way.

## Keeping a lab working

From a sidelab checkout, against a disposable launcher:

```bash
task verify:course COURSE=../../projects/keeptrack/labs/run-from-sources CLI_ARGS="--capabilities network"
```

The command runs every block, and each tour step through the lab browser, so it also proves the branch runs from a fresh clone.
What a block must print is written beside it, in a `<!-- verify: -->` comment, described in sidelab's `docs/courses.md`.
