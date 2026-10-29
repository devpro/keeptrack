# Sources

The repository is public, so cloning needs no account.
The lab runs the branch [[ KEEPTRACK_BRANCH ]], a value of `lab.yaml` that a tenant or an account can replace to try another one.

## Clone

1. Clone the branch, with its last commit only:

   <!-- verify: requires=network timeout=180 expect="Author:" -->

   ```bash exec
   cd ~/keeptrack && \
   git clone --depth 1 --branch "${KEEPTRACK_BRANCH}" "${KEEPTRACK_REPOSITORY}" . && \
   git log -1 --stat=120 | head -n 20
   ```

2. Look at the layout, and refresh the file tree of the editor:

   <!-- verify: expect="Keeptrack.slnx" -->

   ```bash exec
   ls ~/keeptrack ~/keeptrack/src ~/keeptrack/test
   ```

   Folder                       | Holds
   -----------------------------|-------------------------------------------------------------
   `src/BlazorApp`              | The web UI, Blazor Server
   `src/WebApi`                 | The REST API
   `src/WebApi.Contracts`       | The DTOs of the API, shared with the web UI
   `src/Domain`                 | Models and services, with no dependency on storage or HTTP
   `src/Infrastructure.MongoDb` | The MongoDB repositories
   `src/Common.*`               | What both applications share, such as the local token issuer
   `test/`                      | Unit, integration and end-to-end tests
   `docs/`                      | One file per subject, indexed in `docs/README.md`
   `scripts/`                   | Node.js and `mongosh` scripts, such as the MongoDB indexes

3. [Open CONTRIBUTING.md](:open:CONTRIBUTING.md), the steps this lab follows, then [open docs/authentication.md](:open:docs/authentication.md), the design of the two sign-in modes.

## Build

1. Restore the NuGet packages and build every project of the solution:

   <!-- verify: requires=network timeout=900 expect="Build succeeded" -->

   ```bash exec
   cd ~/keeptrack && \
   dotnet build
   ```

   > [!NOTE]
   > `Keeptrack.slnx` is the solution, in the XML format of .NET 10.
   > Package versions are set once for the whole repository, in `Directory.Packages.props`.

## Unit tests

1. Run the unit tests of the web UI, which cover the authentication modes among the rest:

   <!-- verify: timeout=600 expect="failed: 0" -->

   ```bash exec
   cd ~/keeptrack && \
   dotnet test --project test/BlazorApp.UnitTests/BlazorApp.UnitTests.csproj --no-build
   ```

   Unit tests need nothing but the SDK.
   Integration tests need MongoDB, which is the next step.
