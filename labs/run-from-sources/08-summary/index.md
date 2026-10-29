# Summary

---

## From the sources, in five commands

Command                                                    | Does
-----------------------------------------------------------|--------------------------------------
`git clone https://github.com/devpro/keeptrack.git`        | Gets the sources
`dotnet build`                                             | Restores and builds the solution
`mongosh <uri> scripts/mongodb-create-index.js`            | Creates the indexes
`dotnet run --project src/WebApi --launch-profile http`    | Serves the API on `localhost:5057`
`dotnet run --project src/BlazorApp --launch-profile http` | Serves the web UI on `localhost:5207`

With MongoDB running, and the settings of `CONTRIBUTING.md` in the environment or in `appsettings.Development.json`.

---

## Without Firebase

- `Authentication:Mode` is `Local` in `BlazorApp`, and `WebApi` gets a `SigningKey` instead of an `Authority`.

- One shared key, issuer and audience, and nothing reached outside the machine.

- Refused in `Production`, by design.

- The tests pick the mode themselves: local unless Firebase credentials are given.

---

## Other ways to run it

- `docker compose --profile mongodb up -d --build` builds both images and runs them with MongoDB, the indexes created on its first start, signing in with the Firebase project of `.env`.

- The images are published on Docker Hub, as `devprofr/keeptrack-webapi` and `devprofr/keeptrack-blazorapp`.

- Rider and Visual Studio open `Keeptrack.slnx`, and run each application with the same profiles.

---

## Next

- The design, one subject per file: `docs/README.md`.

- Contributing: `CONTRIBUTING.md`, for the terms and the tests.

- The repository: [github.com/devpro/keeptrack](https://github.com/devpro/keeptrack).
