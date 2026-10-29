# Labs

Interactive labs written for [sidelab](https://github.com/devpro/sidelab).

Lab                                   | Covers
--------------------------------------|-------------------------------------------------------------------------------------------------
[run-from-sources](run-from-sources/) | Clone, build and run Keeptrack with a local MongoDB and local authentication, then a guided tour

## Shape of a lab

A lab is a directory of numbered steps, each holding an `index.md` and an optional `step.yaml`, with `lab.yaml` at the root carrying the title, the versions and the credentials the lab needs.
A fenced block marked ` ```bash exec ` renders a **Run** button, and `automation.yaml` declares what the lab browser does, with the selectors of the end-to-end page objects.

`run-from-sources` clones the branch named by `KEEPTRACK_BRANCH` in `lab.yaml`, which a tenant or an account can replace under **Environment** in the launcher to try another branch.
The reference data provider keys are optional secrets, set the same way.

## Running a lab locally

A disposable launcher runs from a sidelab checkout, with the lab already registered, and `KEEP=1` leaves it up afterwards:

```bash
cd ~/repos/sidelab
KEEP=1 task verify:course COURSE=<keeptrack>/labs/run-from-sources CLI_ARGS="--steps 2"
```

`<keeptrack>` is the path of this clone.
The run prints the launcher address, `http://localhost:<port>`, signed in as `admin` with `verify-course-local-pass`, and **Start** opens the lab.

The provider keys come from `Local.runsettings`, which already holds them for the tests, and `set_sidelab_secrets.sh` puts them on the launcher as secrets of the `admin` account, under the names `lab.yaml` declares:

```bash
LAUNCHER_URL=http://localhost:<port> labs/set_sidelab_secrets.sh
```

No value is typed, printed or written to a file, and a key missing from `Local.runsettings` is left unset, its type staying unlinked in the lab.
A session started before the secrets were set does not have them, so the lab is started again.
`task verify:course:stop` stops the launcher and removes its data, the secrets included.

## Keeping a lab working

Against the launcher above:

```bash
LAUNCHER_URL=http://localhost:<port> ADMIN_USERNAME=admin ADMIN_PASSWORD=verify-course-local-pass \
  npm run verify:course -- <keeptrack>/labs/run-from-sources --capabilities network
```

The command runs every block, from the setup to both applications answering, so it also proves the branch runs from a fresh clone.
The guided tour has no block: it is links acting in the browser, played by a person, and `sidelab-cli automation run` plays its actions in a row.
What a block must print is written beside it, in a `<!-- verify: -->` comment, described in sidelab's `docs/courses.md`.
