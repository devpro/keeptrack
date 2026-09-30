# Contributor guide

[![GitLab Pipeline Status](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/pipeline.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/pipelines)
[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=main)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=main)

Steps to run, debug and develop the application locally.
Architecture and conventions are in [AGENTS.md](AGENTS.md), deployment in [docs/operations.md](docs/operations.md).

## License and contribution terms

Keeptrack is licensed under the [PolyForm Strict License 1.0.0](LICENSE), which by itself does not allow making changes or new works based on the software.
As an exception, the licensor grants you permission to modify the software solely for the purpose of developing, testing, and submitting contributions to the official repository (<https://github.com/devpro/keeptrack>).
Running the application locally while developing a contribution is covered by the license's personal-use permission.

By submitting a contribution in any form, you grant Bertrand THOMAS a perpetual, worldwide, irrevocable, royalty-free, sublicensable license over that contribution.
This grant covers using, reproducing, modifying, distributing, and relicensing it as part of Keeptrack, under any terms, including commercial ones.
You confirm that you have the right to grant this license for your contribution.
If you do not agree with these terms, do not submit a contribution.

## Requirements

1. [.NET 10.0 SDK](https://dotnet.microsoft.com/download).
2. Node.js, for the scripts in `scripts/`.
3. A MongoDB database, for example:

   ```bash
   docker run --name mongodb -d -p 27017:27017 mongo:8.2
   ```

   A local `mongod` or a [MongoDB Atlas](https://cloud.mongodb.com/) cluster works too.
   Create the indexes with [`mongosh`](https://www.mongodb.com/docs/mongodb-shell/), which is idempotent and safe to re-run:

   ```bash
   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/mongodb-create-index.js
   ```

4. A Firebase project with Authentication enabled (Google and GitHub providers).

## Configuration

Settings are read from `appsettings.Development.json` or from environment variables, where `:` becomes `__`.

### Web API

Template for `src/WebApi/appsettings.Development.json`:

```json
{
  "AllowedOrigins": [
    "https://localhost:7042",
    "http://localhost:5207"
  ],
  "Authentication": {
    "JwtBearer": {
      "Authority": "https://securetoken.google.com/<firebase-project-id>",
      "TokenValidation": {
        "Issuer": "https://securetoken.google.com/<firebase-project-id>",
        "Audience": "<firebase-project-id>"
      }
    }
  },
  "Features": {
    "IsScalarEnabled": true,
    "IsHttpsRedirectionEnabled": false
  },
  "Infrastructure": {
    "MongoDB": {
      "ConnectionString": "mongodb://localhost:27017",
      "DatabaseName": "keeptrack_dev"
    }
  },
  "Tmdb": { "ApiKey": "<tmdb-api-key>" },
  "Igdb": { "ClientId": "<twitch-client-id>", "ClientSecret": "<twitch-client-secret>" },
  "Rawg": { "ApiKey": "<rawg-api-key>" },
  "Discogs": { "Token": "<discogs-personal-access-token>" },
  "GoogleBooks": { "ApiKey": "<google-books-api-key>" },
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "KeepTrack": "Debug"
    }
  }
}
```

`ReferenceData:BookProvider` (default `googlebooks`) and `ReferenceData:VideoGameProvider` (default `igdb`) select the default provider of the two multi-provider domains.

### Reference data providers

A provider with no credentials is skipped: items of that type stay unlinked instead of failing.

Domain           | Provider                                                                   | Settings                             | How to get them
-----------------|----------------------------------------------------------------------------|--------------------------------------|----------------
TV shows, movies | [TMDB](https://www.themoviedb.org/)                                        | `Tmdb:ApiKey`                        | Free account, then a v3 key at [themoviedb.org/settings/api](https://www.themoviedb.org/settings/api)
TV shows, movies | [OMDb](https://www.omdbapi.com/) (IMDb ratings, optional)                  | `Omdb:ApiKey`                        | Free key at [omdbapi.com/apikey.aspx](https://www.omdbapi.com/apikey.aspx)
Video games      | [IGDB](https://api-docs.igdb.com/) (default)                               | `Igdb:ClientId`, `Igdb:ClientSecret` | Register an application at [dev.twitch.tv/console/apps](https://dev.twitch.tv/console/apps), the token is fetched and renewed by the app
Video games      | [RAWG](https://rawg.io/apidocs) (admin search only)                        | `Rawg:ApiKey`                        | Free account at [rawg.io/apidocs](https://rawg.io/apidocs)
Albums           | [Discogs](https://www.discogs.com/developers)                              | `Discogs:Token`                      | Personal access token at [discogs.com/settings/developers](https://www.discogs.com/settings/developers)
Books            | [Google Books](https://developers.google.com/books) (default)              | `GoogleBooks:ApiKey`                 | Enable the Books API in [Google Cloud Console](https://console.cloud.google.com/) and create an API key
Books            | [Open Library](https://openlibrary.org/), [BnF](https://catalogue.bnf.fr/) | none                                 | Keyless

### Blazor app

Key                                       | Required | Default value
------------------------------------------|----------|--------------
`AllowedHosts`                            | false    | `"*"`
`Features:IsHttpsRedirectionEnabled`      | false    | `true`
`Firebase:WebAppConfiguration:ApiKey`     | true     | `""`
`Firebase:WebAppConfiguration:AuthDomain` | true     | `""`
`Firebase:WebAppConfiguration:ProjectId`  | true     | `""`
`Firebase:ServiceAccount`                 | true     | `""`
`Logging:LogLevel:Default`                | false    | `"Information"`
`Logging:LogLevel:Microsoft.AspNetCore`   | false    | `"Warning"`
`WebApi:BaseUrl`                          | true     | `""`

### Roles

An account with no `role` claim is a free preview account (movies and TV shows only, capped by `Features:FreeTierItemLimit`).
`role: "member"` unlocks every collection, `role: "admin"` adds the reference data admin pages and implies membership.
A claim is picked up at the next sign-in.

Set one with the project's service account key (**Project settings > Service accounts** in the Firebase console):

```bash
node scripts/firebase-user-role.js ./path/to/serviceAccount.json user@example.com admin
node scripts/firebase-user-role.js ./path/to/serviceAccount.json user@example.com --show
```

### Test users

`scripts/firebase-create-user.js` creates a Firebase user through the public sign-up endpoint, so it needs only `FIREBASE_APIKEY`:

```bash
node scripts/firebase-create-user.js
node scripts/firebase-create-user.js someone@example.com "a specific password"
```

Omitted, the email and a strong password are generated and printed with the new uid.
The account starts with no role.

## Run

```bash
dotnet restore
dotnet build
dotnet run --project src/WebApi      # https://localhost:5011/
dotnet run --project src/BlazorApp   # https://localhost:7042/
```

## Tests

Project                          | Needs
---------------------------------|------
`test/WebApi.UnitTests`          | Nothing
`test/BlazorApp.UnitTests`       | Nothing
`test/WebApi.IntegrationTests`   | MongoDB and a Firebase test user
`test/BlazorApp.PlaywrightTests` | Skipped unless `E2E_ENABLED=true`, see [End-to-end tests](#end-to-end-tests)

`test/Testing.Shared` is shared hosting and Firebase infrastructure, not a test project.

```bash
dotnet test
dotnet test --project test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test --filter-method "*CarResourceTest*"
```

`--filter-method` takes one glob pattern, with no `|` or `,` alternation, so several patterns are several runs.

**`--settings Local.runsettings` does not work from the command line**: the runner is `Microsoft.Testing.Platform` and that flag makes it run zero tests (exit code 5).
Rider and Visual Studio read `Local.runsettings` themselves, and on the command line `scripts/load-runsettings.js` exports its values:

```bash
eval "$(node scripts/load-runsettings.js)"
dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj
```

The values are never converted to plain `NAME=value` lines and sourced: shell expansion silently truncates a password containing `$`, which surfaces as Firebase answering `INVALID_PASSWORD`.

### Integration tests

Required variables:

- `Infrastructure__MongoDB__ConnectionString`.
  The database defaults to `keeptrack_integrationtests`, and a name containing `dev`, `prod` or `staging` is refused.
- `FIREBASE_APIKEY`: **Project settings > General > Web API Key** in the Firebase console.
- `FIREBASE_USERNAME`, `FIREBASE_PASSWORD`: a dedicated test user, carrying `role: "admin"` so the admin endpoints are covered.
- `Authentication__JwtBearer__Authority`, `Authentication__JwtBearer__TokenValidation__Issuer`: `https://securetoken.google.com/<firebase-project-id>`.
- `Authentication__JwtBearer__TokenValidation__Audience`: `<firebase-project-id>`.

Optional variables:

- `KESTREL_WEBAPP_URL` targets an already running API instead of hosting one.
- `GoogleBooks__ApiKey` exercises the default book provider in `BookProviderSearchAndLinkResourceTest`, whose cases skip on a provider answering 502.
- `REFERENCE_SYNC_POLL_ENABLED=true` runs `SyncNow_PollingReachesACompletedResult`, a full sync against the live providers.

Template for `Local.runsettings` at the repository root (gitignored, never committed):

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <AllowedOrigins__0>http://localhost:5207</AllowedOrigins__0>
      <Infrastructure__MongoDB__ConnectionString>mongodb://localhost:27017</Infrastructure__MongoDB__ConnectionString>
      <Authentication__JwtBearer__Authority>https://securetoken.google.com/xxxx</Authentication__JwtBearer__Authority>
      <Authentication__JwtBearer__TokenValidation__Issuer>https://securetoken.google.com/xxxx</Authentication__JwtBearer__TokenValidation__Issuer>
      <Authentication__JwtBearer__TokenValidation__Audience>xxxx</Authentication__JwtBearer__TokenValidation__Audience>
      <FIREBASE_APIKEY>xxxx</FIREBASE_APIKEY>
      <FIREBASE_USERNAME>xxxx</FIREBASE_USERNAME>
      <FIREBASE_PASSWORD>xxxx</FIREBASE_PASSWORD>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

In Rider, the same variables can be set in **Settings > Build, Execution, Deployment > Unit Testing > Test Runner**.

Tests leave the database as they found it.
A document count per collection before and after a run is how to check it:

```bash
mongosh --quiet mongodb://localhost:27017/keeptrack_integrationtests --eval 'const o={};db.getCollectionNames().sort().forEach(c=>o[c]=db.getCollection(c).countDocuments({}));print(JSON.stringify(o));'
```

### End-to-end tests

`test/BlazorApp.PlaywrightTests` drives the real Blazor app in a browser.
Install the browser once, after a first build:

```bash
pwsh test/BlazorApp.PlaywrightTests/bin/Debug/net10.0/playwright.ps1 install chromium
```

Mode        | Trigger                           | Hosting
------------|-----------------------------------|--------
Self-hosted | `E2E_ENABLED=true`, no target URL | Both apps in the test process, so breakpoints in `BlazorApp` and `WebApi` are hit
Live        | `E2E_TARGET_URL` set              | Drives an already running deployment
Read-only   | `E2E_READONLY=true`               | Every mutating test skips, paired with `E2E_TARGET_URL`

Self-hosted mode needs the integration test variables above (except `FIREBASE_USERNAME`/`FIREBASE_PASSWORD`, an ephemeral admin user is created and deleted),
plus `Tmdb__ApiKey`, `Igdb__ClientId`, `Igdb__ClientSecret` and `Discogs__Token`, since the smoke tests link real titles.
The database defaults to `keeptrack_e2e`, independently of `Infrastructure__MongoDB__DatabaseName`, so the two suites never share one.

```bash
eval "$(node scripts/load-runsettings.js)"
export E2E_ENABLED=true
dotnet test --project test/BlazorApp.PlaywrightTests/BlazorApp.PlaywrightTests.csproj
```

Variable                       | Default                             | Purpose
-------------------------------|-------------------------------------|--------
`E2E_ENABLED`                  | `false`                             | Master switch
`E2E_TARGET_URL`               | empty                               | Live mode: BlazorApp base URL
`E2E_WEBAPI_URL`               | empty                               | Live mode: WebApi base URL, required unless read-only
`E2E_READONLY`                 | `false`                             | Skips every mutating test, user creation and seeding
`E2E_USERNAME`, `E2E_PASSWORD` | empty                               | Existing account, required in live mode, else an ephemeral admin is created
`E2E_MONGODB_DATABASE`         | `keeptrack_e2e`                     | Database of the self-hosted apps
`E2E_HEADLESS`                 | `true`                              | `false` shows the browser
`E2E_SLOWMO_MS`                | `0`                                 | Delay before each Playwright action
`E2E_BROWSER`                  | `chromium`                          | `chromium`, `firefox` or `webkit`
`E2E_TRACE`                    | `on-failure`                        | `off`, `on` or `on-failure`
`E2E_MOBILE_CHECK`             | `false`                             | Runs `MobileScreenshotTest`, captures every page at a phone viewport
`E2E_MOBILE_DIR`               | `bin/<config>/net10.0/mobile-shots` | Where those captures go
`GOOGLE_BOOKS_SMOKE_ENABLED`   | `false`                             | Runs `GoogleBooksSmokeTest`, needs `GoogleBooks__ApiKey`

`E2E_HEADLESS=false` with `E2E_SLOWMO_MS=250` shows a run, `PWDEBUG=1` opens the Playwright inspector.

A failed test leaves a full-page screenshot and a Playwright trace in `test/BlazorApp.PlaywrightTests/bin/<config>/net10.0/e2e-diagnostics`, and prints their paths in its output.
A trace opens at [trace.playwright.dev](https://trace.playwright.dev).

## Container images

```bash
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```

## Continuous integration

[IstarCI](https://github.com/devpro/istarci) is recommended but optional: the CI is the GitHub Actions pipeline, and IstarCI runs it locally on every commit, in containers, and blocks `git push` when it failed.
It is installed once per machine from GitHub Packages, with a `~/.npmrc` token that reads `@devpro` packages:

```bash
npm install --global @devpro/istarci
istarci daemon install
istarci daemon start
task ci:setup   # registers this repository and installs the pre-push hook
```

Every commit made afterward runs in the background:

```bash
task ci        # the runs of the recent commits
task ci:logs   # the output of the last run
```

The image of each job is set in `.istarci.yml`.
When working on IstarCI itself, `task ci:from-clone` runs the pipeline once from a clone in `~/repos/istarci` or `ISTARCI_DIR`, without the package.
