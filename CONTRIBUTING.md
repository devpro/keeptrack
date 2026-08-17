# Contributor guide

[![GitLab Pipeline Status](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/pipeline.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/pipelines)
[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=main)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=main)

Follow this steps to run/debug/develop the application on your machine.

For an environment, look at [operations.md](docs/operations.md).

## License and contribution terms

Keeptrack is licensed under the [PolyForm Strict License 1.0.0](LICENSE), which by itself does not allow making changes or new works based on the software.
As an exception, the licensor grants you permission to modify the software solely for the purpose of developing, testing, and submitting contributions to the official repository (<https://github.com/devpro/keeptrack>).
Running the application locally while developing a contribution is covered by the license's personal-use permission.

By submitting a contribution in any form, you grant Bertrand THOMAS a perpetual, worldwide, irrevocable, royalty-free, sublicensable license over that contribution.
This grant covers using, reproducing, modifying, distributing, and relicensing it as part of Keeptrack, under any terms, including commercial ones.
You confirm that you have the right to grant this license for your contribution.
If you do not agree with these terms, do not submit a contribution.

## Design

The application source code is in the following .NET projects:

Project name             | Technology | Project type
-------------------------|------------|-------------
`BlazorApp`              | ASP.NET 10 | Blazor Server web application
`Common.System`          | .NET 10    | Library
`Domain`                 | .NET 10    | Library
`Infrastructure.MongoDb` | .NET 10    | Library
`WebApi`                 | ASP.NET 10 | Web application (REST API)
`WebApi.Contracts`       | .NET 10    | Library

The application is using the following .NET packages (via NuGet):

Name                | Description
--------------------|------------
`FirebaseAdmin`     | Firebase
`MongoDB.Bson`      | MongoDB BSON
`MongoDB.Driver`    | MongoDB .NET Driver
`Scalar.AspNetCore` | OpenAPI web UI

## Requirements

1. [.NET 10.0 SDK](https://dotnet.microsoft.com/download)

2. MongoDB database

    Several options:

    - Local server
  
    ```bash
    cd D:/Programs/mongodb-8.2/bin
    md log
    md data
    mongod --logpath log/mongod.log --dbpath data --port 27017
    ```
  
    - [Docker](https://hub.docker.com/_/mongo/)
  
    ```bash
    docker run --name mongodb -d -p 27017:27017 mongo:8.2
    ```
  
    - [MongoDB Atlas](https://cloud.mongodb.com/) cluster

    Once it's running, create the app's indexes with [`mongosh`](https://www.mongodb.com/docs/mongodb-shell/), pointed at the database you're using (`keeptrack_dev` by default - see [Web API settings](#web-api-settings) below):

    ```bash
    mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/mongodb-create-index.js
    ```

    `scripts/mongodb-create-index.js` is idempotent, so it's safe to run again after pulling changes to it or against a database that already has these indexes.

3. IDE: Rider, Visual Studio, Visual Studio Code

## Configuration

### Web API settings

Key                                       | Description
------------------------------------------|------------
`Infrastructure:MongoDB:ConnectionString` | MongoDB connection string
`Infrastructure:MongoDB:DatabaseName`     | MongoDB database name
`Tmdb:ApiKey`                             | TMDB v3 API key, used to auto-match shows/movies to episode titles and synopses (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) below)
`Rawg:ApiKey`                             | RAWG API key, the secondary video game provider (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) below)
`Igdb:ClientId`                           | Twitch application client id, used by the default video game provider IGDB to auto-match games to synopses/cover art/platforms (see Reference data below)
`Igdb:ClientSecret`                       | Twitch application client secret, exchanged with the client id for the app access token every IGDB request carries
`Discogs:Token`                           | Discogs personal access token, used to auto-match albums to synopses/cover art/genres (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) below)
`GoogleBooks:ApiKey`                      | Google Books API key, used to auto-match books to synopses/cover art/language/genres (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) below)
`ReferenceData:BookProvider`              | Default `IBookReferenceClient` used for automatic/background book matching (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) below). Default: `googlebooks`
`ReferenceData:VideoGameProvider`         | Default `IVideoGameReferenceClient` used for automatic/background video game matching, for adopting an id onto references linked before it, and as Explore's discovery provider. Default: `igdb`

This values can be easily provided as environment variables (replace ":" by "__") or by configuration (json).

Template for `src/WebApi/appsettings.Development.json`:

```json
{
  "AllowedOrigins": [
    "http://localhost:5207",
    "https://localhost:7042"
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
  "Tmdb": {
    "ApiKey": "<your-tmdb-api-key>"
  },
  "Igdb": {
    "ClientId": "<your-twitch-client-id>",
    "ClientSecret": "<your-twitch-client-secret>"
  },
  "Rawg": {
    "ApiKey": "<your-rawg-api-key>"
  },
  "Discogs": {
    "Token": "<your-discogs-personal-access-token>"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "KeepTrack": "Debug"
    }
  }
}
```

### Reference data (TMDB, Open Library, RAWG, Discogs)

Episode titles, synopses, cover art, and the "what should I watch next" experience are backed by shared reference collections, one per trackable type, each populated from a different external provider rather than typed in by hand:

Type              | Provider                                      | Setting                               | API key required?
------------------|-----------------------------------------------|---------------------------------------|------------------
TV shows / Movies | [TMDB](https://www.themoviedb.org/)           | `Tmdb:ApiKey`                         | Yes
Books             | [Open Library](https://openlibrary.org/)      | *(none)*                              | No
Video Games       | [IGDB](https://api-docs.igdb.com/)            | `Igdb:ClientId` + `Igdb:ClientSecret` | Yes (Twitch application)
Video Games (alt) | [RAWG](https://rawg.io/apidocs)               | `Rawg:ApiKey`                         | Yes
Albums            | [Discogs](https://www.discogs.com/developers) | `Discogs:Token`                       | Yes (personal access token)

1. **TMDB**: create a free account, then generate a v3 API key at [themoviedb.org/settings/api](https://www.themoviedb.org/settings/api).
   Set `Tmdb:ApiKey` (or the `Tmdb__ApiKey` environment variable) to that key.
2. **Open Library**: nothing to configure - its search/cover-image API is free and keyless.
3. **IGDB**: IGDB is part of Twitch and has no key of its own - register an application at [dev.twitch.tv/console/apps](https://dev.twitch.tv/console/apps), then set `Igdb:ClientId` and `Igdb:ClientSecret` (or
   `Igdb__ClientId`/`Igdb__ClientSecret`) to that application's pair.
   The app exchanges them for an access token itself and refreshes it as needed; there is nothing to renew by hand.
4. **RAWG**: create a free account, then generate an API key at [rawg.io/apidocs](https://rawg.io/apidocs).
   Set `Rawg:ApiKey` (or `Rawg__ApiKey`) to that key.
   Only needed for admin search/linking against RAWG; background refresh never calls it once IGDB is the default.
5. **Discogs**: create a free account, then generate a personal access token at [discogs.com/settings/developers](https://www.discogs.com/settings/developers).
   Set `Discogs:Token` (or `Discogs__Token`) to that token.
6. **Google Books**: create a project in [Google Cloud Console](https://console.cloud.google.com/), enable the Books API, then generate an API key.
   Set `GoogleBooks:ApiKey` (or `GoogleBooks__ApiKey`) to that key.

Without a key/token for a given provider, new items of that type simply stay unresolved (no synopsis, no cover art) instead of erroring.
The app degrades gracefully per type - it just won't auto-match that type until the corresponding setting is provided.

Books and video games are each resolved through a provider-agnostic interface (`IBookReferenceClient`/`IVideoGameReferenceClient`, `src/WebApi/ReferenceData/`) - the two domains with more than one provider registered at once.
Video games have `IgdbClient` (key `igdb`, the default) and `RawgClient` (key `rawg`), the latter kept registered so an admin can still search/link with it and so references linked through it keep their stored `rawg`/`metacritic` ratings.
Background refresh only ever calls the *default* provider, unlike books - a reference that hasn't adopted an IGDB id keeps the data it has rather than being re-fetched from a provider the operator didn't select;
a reference linked before IGDB became the default adopts an IGDB id automatically during a periodic sync pass, provided the match is unambiguous.
For books:
`GoogleBooksClient` (key `googlebooks`, the default - real synopses, cover art, language and the widest catalogue coverage of the three, including manga/comics),
`OpenLibraryClient` (key `openlibrary`, no API key needed, kept as a fallback), and `BnfClient` (key `bnf`, BnF's free/keyless SRU Catalogue général, also kept as a fallback -
in practice its records tend to have long library-catalogue-style titles, no cover art, and little to no synopsis, so it's rarely the best choice, but it can still surface a French title neither of the other two has).
`src/WebApi/Program.cs` registers every implemented provider unconditionally; the shared `ReferenceClientRegistry<TClient>` resolves a provider by key,
falling back to `ReferenceData:BookProvider`/`ReferenceData:VideoGameProvider` (or the `ReferenceData__*` environment variables) when none is specified.
An admin can pick any registered provider per search/link action from the reference-data admin page or an item's own detail page, regardless of that default.
To add a new provider, implement the domain's interface (a new client class alongside the existing ones, plus its own settings class if it needs credentials, following `RawgSettings`/`DiscogsSettings`)
and add one registration block to `Program.cs` - no changes needed to the registry, enrichment service, admin controller, or admin UI.
Nothing else in the app needs to change, since `ReferenceEnrichmentService`/`ReferenceDataAdminController` only depend on the interface and read the active provider's key from `IReferenceProviderClient.ProviderKey`.

### Admin role

The reference-data curation page (`/admin/reference-data`, and its underlying `api/reference-data/*` admin endpoints) is restricted to users carrying a Firebase custom claim `role: "admin"`.
There's no in-app way to grant this - it's a one-off action against your own Firebase project, e.g. with the [Firebase Admin SDK](https://firebase.google.com/docs/auth/admin/custom-claims) for Node:

```javascript
const admin = require("firebase-admin");
admin.initializeApp();
admin.auth().setCustomUserClaims("<firebase-user-uid>", { role: "admin" });
```

The claim is embedded directly in that user's ID token on their next sign-in (existing sessions need to sign out/in again to pick it up).

### Membership role (free preview tier)

Any account that can sign in (Google/GitHub through Firebase Auth) but carries **no** `role` claim is a *free preview* account:
it only gets movies and TV shows, capped at `Features:FreeTierItemLimit` items per collection (default 20; episodes get 100x that so ticking off a watch-through never feels rationed).
Every other collection (books, albums, playlists, video games, cars, houses) and the TV Time import require the `MemberOnly` policy.

Grant a membership exactly like the admin role above, with `role: "member"` instead:

```javascript
admin.auth().setCustomUserClaims("<firebase-user-uid>", { role: "member" });
```

`role: "admin"` implies membership (the `MemberOnly` policy accepts both values), so the owner's account needs nothing extra.
As with the admin claim, the user must sign out and back in to pick it up.
Enforcement lives in the API (`MemberOnly` policy attributes plus the creation quota in `DataCrudControllerBase.Post`) - the Blazor nav hiding restricted sections is UX, not security.

[Install Deno](https://docs.deno.com/runtime/getting_started/installation/):

```cmd
winget install DenoLand.Deno
```

Run the script:

```cmd
deno run -A scripts/firebase-user-role.js ./path/to/serviceAccount.json user@example.com admin
```

### Blazor Server App settings

Key                                     | Required | Default value
----------------------------------------|----------|--------------
AllowedHosts                            | false    | "*"
Features:IsHttpsRedirectionEnabled      | false    | true
Firebase:WebAppConfiguration:ApiKey     | true     | ""
Firebase:WebAppConfiguration:AuthDomain | true     | ""
Firebase:WebAppConfiguration:ProjectId  | true     | ""
Firebase:ServiceAccount                 | true     | ""
Logging:LogLevel:Default                | false    | "Information"
Logging:LogLevel:Microsoft.AspNetCore   | false    | "Warning"
WebApi:BaseUrl                          | true     | ""

## Run

```bash
dotnet restore

dotnet build

# run the API (https://localhost:5011/)
dotnet run --project src/WebApi

# run the Blazor WebAssembly web app (https://localhost:5021)
dotnet run --project src/BlazorApp
```

## Tests

The solution has three test projects:

- `test/WebApi.UnitTests` has no external dependencies.
- `test/WebApi.IntegrationTests` needs a running MongoDB and a Firebase test user, since it boots the real Web API and calls it like a real client would.
- `test/BlazorApp.PlaywrightTests` is a Playwright end-to-end suite; it self-skips unless `E2E_ENABLED=true` (see [End-to-end (Playwright) tests](#end-to-end-playwright-tests) below), so it needs nothing extra for a plain `dotnet test`.

`test/Testing.Shared` is not a test project itself - it's the shared hosting/Firebase-auth infrastructure `WebApi.IntegrationTests` and `BlazorApp.PlaywrightTests` both build on, so neither duplicates it.

Run everything:

```bash
dotnet test
```

Run just one project:

```bash
dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj
```

Run a single test by fully qualified name (works for either project):

```bash
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.Services.WatchNextServiceTest.ComputeInProgressShows_IncludesShowWithAConfirmedAiredUnwatchedNextEpisode"
```

`--filter-method` also accepts a wildcard, e.g. `--filter-method "*CarResourceTest*"` to run every test in a class.
It's a single glob pattern, not a real filter expression: it does not support `|`/`,` alternation to combine multiple patterns in one run (that just prints the CLI help instead of running anything).
So run each pattern as its own `dotnet test` invocation.
This project's test runner is `Microsoft.Testing.Platform` (`UseMicrosoftTestingPlatformRunner`, xunit v3), which does **not** understand the classic VSTest `--settings <file>.runsettings` flag - passing it also just prints the help.
`Local.runsettings` (below) is read automatically by Rider/Visual Studio for IDE-driven runs; for a CLI run, export the same values as environment variables instead (see "Integration tests" below).

`scripts/load-runsettings.js` does that export for an existing `Local.runsettings`, so the values only have to be written once:

```bash
eval "$(node scripts/load-runsettings.js)"
dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "*WishlistResourceTest*"
```

**Do not source the file's values as plain `NAME=value` lines instead.**
Sourcing runs every value through shell expansion, so a password containing `$` silently loses everything from the `$` to the next non-word character.
The only symptom is Firebase answering `INVALID_PASSWORD`, which reads as a wrong password rather than as a mangled one.
The script single-quotes every value, escapes any embedded `'`, decodes XML entities, and skips commented-out variables.
The PowerShell one-liner further down has no such trap, because `Set-Item -Value` never re-parses what it is given.

### Unit tests

No configuration needed - `dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj` works as soon as the solution restores.

### Integration tests

These need two things configured before they'll pass:

1. **A MongoDB instance** (see [Requirements](#requirements) above), pointed at by `Infrastructure__MongoDB__ConnectionString`.
   The database name is **not** something you have to set: this suite runs against `keeptrack_integrationtests` unless `Infrastructure__MongoDB__DatabaseName` says otherwise, and the e2e suite defaults to its own `keeptrack_e2e` -
   so the two never share one, and an IDE that sets test environment variables solution-wide (Rider) needs no per-suite juggling.
   Whatever the name resolves to is pushed into the host's configuration, which is what stops the silent failure behind all this:
   the in-process host runs as `Development`, so with nothing configured it would fall back to `src/WebApi/appsettings.Development.json` - your own `keeptrack_dev` - and the whole suite would happily create and delete documents in it.
   A name that looks like a real database (`dev`/`prod`/`staging`/`preprod`) still refuses to start.
   Running `scripts/mongodb-create-index.js` against it first is recommended (keeps behavior closest to production) but not required for the tests themselves to pass.
   See [Requirements](#requirements) above for the exact `mongosh` command (swap in `keeptrack_integrationtests` for the database name).

   Tests leave the database exactly as they found it - every test registers its cleanup as it creates data, so a mid-test failure still cleans up.
   If you're adding a test, use the registration helpers (`CreateAsync`, `TrackResource`, `TrackDocument`, `TrackResourcesMatching`, `TrackCleanup`) rather than a `try`/`finally`; see CLAUDE.md's "Tests" section for which to reach for.
   The property is worth re-checking after a change, and a document-count diff across a run is the way to do it (test results alone won't tell you - a delete filter that matches nothing reports success):

   ```bash
   mongosh --quiet mongodb://localhost:27017/keeptrack_integrationtests --eval \
     'const o={};db.getCollectionNames().sort().forEach(c=>o[c]=db.getCollection(c).countDocuments({}));print(JSON.stringify(o));'
   ```

2. **A Firebase test user**, since `ResourceTestBase.Authenticate()` performs a real Firebase sign-in to obtain a bearer token:
   - `FIREBASE_APIKEY`: the Firebase project's Web API key (Firebase Console → Project settings → General → Web API Key).
   - `FIREBASE_USERNAME` / `FIREBASE_PASSWORD`: the email/password of a real user created in that project (Firebase Console → Authentication → Users → Add user).
     Use a dedicated test account, not a personal one.
   - `Authentication__JwtBearer__Authority`, `..__TokenValidation__Issuer`, `..__TokenValidation__Audience`: all `https://securetoken.google.com/<firebase-project-id>`.
     See the [Web API settings](#web-api-settings) above for the Issuer/Audience split.
     This is what lets the API-under-test validate the token issued by that same Firebase project.

One test is additionally opt-in: `SyncNow_PollingReachesACompletedResult` polls a full reference-data sync to completion against the live providers,
so its duration grows with the database and it can flake on provider latency/rate limits.
It self-skips unless `REFERENCE_SYNC_POLL_ENABLED=true`; set that when working on the sync pipeline (the job-start half of the lifecycle stays covered by default).

Provide all of this as environment variables (works everywhere, including CI - see `.github/workflows/ci.yaml` for how the pipeline supplies its own test account), for example:

```bash
export AllowedOrigins__0=http://localhost:5207
export Infrastructure__MongoDB__ConnectionString=mongodb://localhost:27017
export Infrastructure__MongoDB__DatabaseName=keeptrack_integrationtests
export Authentication__JwtBearer__Authority=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Issuer=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Audience=<firebase-project-id>
export FIREBASE_APIKEY=<web-api-key>
export FIREBASE_USERNAME=<test-user-email>
export FIREBASE_PASSWORD=<test-user-password>

dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj
```

Or, for an IDE-driven workflow, put the same values in a `Local.runsettings` file at the repository root (gitignored - never commit it) so Rider/Visual Studio pick them up automatically for test runs:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <AllowedOrigins__0>http://localhost:5207</AllowedOrigins__0>
      <Infrastructure__MongoDB__ConnectionString>mongodb://localhost:27017</Infrastructure__MongoDB__ConnectionString>
      <Infrastructure__MongoDB__DatabaseName>keeptrack_integrationtests</Infrastructure__MongoDB__DatabaseName>
      <Authentication__JwtBearer__Authority></Authentication__JwtBearer__Authority>
      <Authentication__JwtBearer__TokenValidation__Issuer></Authentication__JwtBearer__TokenValidation__Issuer>
      <Authentication__JwtBearer__TokenValidation__Audience></Authentication__JwtBearer__TokenValidation__Audience>
      <!-- <KESTREL_WEBAPP_URL>xxxx</KESTREL_WEBAPP_URL> -->
      <FIREBASE_APIKEY>xxxx</FIREBASE_APIKEY>
      <FIREBASE_USERNAME>xxxx</FIREBASE_USERNAME>
      <FIREBASE_PASSWORD>xxxx</FIREBASE_PASSWORD>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Or in Rider, in "File | Settings | Build, Execution, Deployment | Unit Testing | Test Runner", set the same three Firebase variables directly so they apply to every test run in the IDE without a file.

Set `KESTREL_WEBAPP_URL` to target a specific already-running instance instead of letting the tests spin up their own.

Provider keys (`Tmdb__ApiKey`, `GoogleBooks__ApiKey`, ...) are optional for this suite: only `BookProviderSearchAndLinkResourceTest` calls a provider live, and each of its cases skips itself - reporting which provider and why -
when that provider answers 502, which is what an unconfigured key or a provider outage both come to.
Supply `GoogleBooks__ApiKey` to actually exercise the default book provider's search+link path locally; its keyless BnF case runs either way.

The standard test user above now carries the `role: admin` custom claim (set via `scripts/firebase-user-role.js`, see [Admin role](#admin-role) above).
So `ReferenceDataAdminResourceTest` and any other admin-gated endpoint can be exercised end-to-end over HTTP with the same single test account.
There's no separate non-admin test account, so there's no automated coverage of the "AdminOnly" policy actually rejecting a non-admin caller; that would need a second Firebase test user without the claim.
The underlying Mongo query logic (`SetReferenceIdForTitleYearAsync`, `FindDistinctUnresolvedTitleYearsAsync`) is still covered directly against a real database in `TvShowReferenceLinkingTest`.
This test resolves repositories from the test host's DI container instead of going over HTTP.

### End-to-end (Playwright) tests

`test/BlazorApp.PlaywrightTests` drives the real Blazor Server app in a real browser (Chromium by default) through Microsoft Playwright.
It self-skips entirely unless `E2E_ENABLED=true`.
So it needs no extra setup for a plain `dotnet test`.

In Rider, open settings using `Ctrl` + `Alt` + `S` (or with File > Settings), navigate to **Build, Execution, Deployment** > **Unit Testing** > **Test Runner**, and add the variable in Environment variables.

One-time browser install, after the project has been built at least once:

```bash
pwsh test/BlazorApp.PlaywrightTests/bin/Debug/net10.0/playwright.ps1 install chromium
```

The suite runs three ways from the same code, controlled by environment variables:

Mode        | Trigger                           | Hosting
------------|-----------------------------------|--------
Integration | `E2E_ENABLED=true`, no target URL | Both apps self-hosted in-process on dynamic ports, same MongoDB/Firebase settings as the integration tests above
Live        | `E2E_TARGET_URL` set              | Nothing hosted; the browser drives an already-running deployment
Read-only   | `E2E_READONLY=true`               | No provisioning, no seeding, every mutating test skips - pair with `E2E_TARGET_URL` against a real environment

Variable                     | Default                             | Purpose
-----------------------------|-------------------------------------|--------
`E2E_ENABLED`                | `false`                             | Master switch; every e2e test dynamically skips unless this is `true`
`E2E_TARGET_URL`             | *(empty)*                           | Live mode: base URL of an already-running BlazorApp
`E2E_WEBAPI_URL`             | *(empty)*                           | Live mode: base URL of the matching WebApi, required for seeding/cleanup unless read-only
`E2E_READONLY`               | `false`                             | Skips every mutating test, user creation, and seeding
`E2E_USERNAME`               | *(empty)*                           | Existing account email; empty triggers ephemeral admin user creation (integration mode only)
`E2E_PASSWORD`               | *(empty)*                           | Password for `E2E_USERNAME`
`E2E_MONGODB_DATABASE`       | `keeptrack_e2e`                     | Database the self-hosted apps run against, **defaulted rather than inherited** from `Infrastructure__MongoDB__DatabaseName` - see [Why this suite picks its own database](#why-this-suite-picks-its-own-database)
`E2E_HEADLESS`               | `true`                              | `false` shows the browser window
`E2E_SLOWMO_MS`              | `0`                                 | Milliseconds of delay injected before each Playwright action
`E2E_BROWSER`                | `chromium`                          | `chromium`, `firefox` or `webkit`
`E2E_TRACE`                  | `on-failure`                        | `off`, `on` or `on-failure`; see [Diagnosing a failed run](#diagnosing-a-failed-run) below
`E2E_MOBILE_CHECK`           | `false`                             | Opt-in for `MobileScreenshotTest`, an assertion-free visual-review walkthrough: seeds representative data, captures every page at a phone viewport, cleans up after itself
`E2E_MOBILE_DIR`             | `bin/<config>/net10.0/mobile-shots` | Where `MobileScreenshotTest` writes its captures
`GOOGLE_BOOKS_SMOKE_ENABLED` | `false`                             | Opt-in for `GoogleBooksSmokeTest` (requires `GoogleBooks:ApiKey` to be configured)

Integration mode (the common local/CI case) reuses the same MongoDB/Firebase variables as the integration tests above, pointed at a dedicated database (e.g. `keeptrack_e2e`), plus `E2E_ENABLED=true`:

```bash
export E2E_ENABLED=true
export Infrastructure__MongoDB__ConnectionString=mongodb://localhost:27017
export Infrastructure__MongoDB__DatabaseName=keeptrack_e2e
export Authentication__JwtBearer__Authority=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Issuer=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Audience=<firebase-project-id>
export FIREBASE_APIKEY=<web-api-key>
export Tmdb__ApiKey=<tmdb-api-key>
export Igdb__ClientId=<twitch-client-id>
export Igdb__ClientSecret=<twitch-client-secret>
export Discogs__Token=<discogs-personal-access-token>

dotnet test test/BlazorApp.PlaywrightTests/BlazorApp.PlaywrightTests.csproj
```

No `FIREBASE_USERNAME`/`FIREBASE_PASSWORD` is needed for this mode.
An ephemeral admin user is created via the Firebase Admin SDK (reusing the Blazor host's own `Firebase:ServiceAccount`) and deleted again at teardown.
Set `E2E_USERNAME`/`E2E_PASSWORD` instead to reuse an existing account.

Self-hosted mode applies the same "never the dev database" guard as the integration suite, for the same reason.
Live mode (`E2E_TARGET_URL`) is exempt, since the deployment owns its own configuration.
Like the integration suite, an e2e run leaves the database as it found it: each smoke test registers its cleanup as it creates data.
The fixture removes its seeded reference document plus the ephemeral user's own preference/background-job rows at teardown.
The one thing deliberately left behind is reference data resolved from a *real* provider title (TMDB's "The Terminator" and its cast, say).
That's shared canonical data deduplicated by provider id, so it's reused on the next run rather than duplicated.

`Tmdb__ApiKey`/`Igdb__ClientId`/`Igdb__ClientSecret`/`Discogs__Token` are required (see [Reference data](#reference-data-tmdb-open-library-rawg-discogs) above for where to get each one), not optional.
`Rawg__ApiKey` is deliberately *not* required: what a smoke test links through is whichever provider is the domain's default, and RAWG stopped being it - no e2e path reaches RAWG unless a test picks it explicitly.
The Movie/TvShow/VideoGame/Album smoke tests link a real, well-known title (e.g. "The Terminator", "Breaking Bad") against the real provider.
So a missing key fails the whole run fast with a clear error, rather than letting those tests fail downstream with a confusing "no results found".
Book needs no key (Open Library), so it's unaffected.

For an IDE-driven workflow, add the same variables to the `Local.runsettings` file described above, for example:

```xml
<E2E_ENABLED>true</E2E_ENABLED>
<Infrastructure__MongoDB__DatabaseName>keeptrack_e2e</Infrastructure__MongoDB__DatabaseName>
<Tmdb__ApiKey>xxxx</Tmdb__ApiKey>
<Igdb__ClientId>xxxx</Igdb__ClientId>
<Igdb__ClientSecret>xxxx</Igdb__ClientSecret>
<Discogs__Token>xxxx</Discogs__Token>
<!-- <E2E_HEADLESS>false</E2E_HEADLESS> -->
<!-- <E2E_SLOWMO_MS>250</E2E_SLOWMO_MS> -->
```

In integration mode both apps run inside the test process, so breakpoints hit in `BlazorApp`/`WebApi` source during a browser click, not just in test code.
Set `E2E_HEADLESS=false` plus `E2E_SLOWMO_MS=250` to watch the run, or `PWDEBUG=1` to open the Playwright inspector.

#### Why this suite picks its own database

An IDE sets test environment variables once for the whole solution (Rider's **Build, Execution, Deployment > Unit Testing > Test Runner** environment variables apply to every test in it), so a database name both suites read could only ever
give them the same one - and removing it to stop that is worse still, since it takes the integration suite's guard with it.
Neither suite reads it as a requirement any more: this one hosts its apps against `E2E_MONGODB_DATABASE` (default `keeptrack_e2e`) and the integration suite against `Infrastructure__MongoDB__DatabaseName` (default
`keeptrack_integrationtests`).
Set neither, and both work, isolated.
There is nothing to switch between runs.

Sharing one database is not neutral.
The integration suite's `sync-now` tests write the real Explore ranking into the shared `explore_catalogue`, and `ExploreSmokeTest` needs that collection to hold nothing but what it seeded -
it asserts on a card count, so a shared database surfaced as `Locator expected to have count '26', but was '44'`, the extra 18 being real films interleaved with the seeded ones by rank.
That test now names the cause instead, and reports the database it actually used.

Set `E2E_MONGODB_DATABASE` if you deliberately want another one (a shared database stays reachable, just never by accident).
`TestDatabaseGuard` checks the name this run will really use, so a `dev`/`prod`/`staging` value still fails fast.

#### Diagnosing a failed run

**Look in `test/BlazorApp.PlaywrightTests/bin/<config>/net10.0/e2e-diagnostics`.**
Every Playwright test in the suite writes there when it fails.
The behavior is `SmokeTestBase.DisposeAsync`, which every test class inherits, not something a test opts into:

- `<test display name>.png`, a full-page screenshot of the browser as the test left it.
  A test-driving more than one page (an anonymous visitor, a share recipient) gets one file per page, suffixed with that page's label (`...-recipient.png`).
- `<test display name>.zip`, the Playwright trace, unless `E2E_TRACE=off`.
  Open it at [trace.playwright.dev](https://trace.playwright.dev) or with `playwright show-trace` for the DOM snapshots, console and network of every step.
  `E2E_TRACE=on` keeps it for passing tests too.

The paths are also printed to the failing test's own output, so a CI log names the files rather than assuming the reader knows the convention.
Capturing them can never fail a run: a page that has already crashed or is mid-navigation is reported and skipped, leaving the test's real failure as the reported one.

Live run against a real deployment, read-only:

```bash
export E2E_ENABLED=true E2E_TARGET_URL=https://keeptrack.example.com E2E_READONLY=true
export E2E_USERNAME=... E2E_PASSWORD=... FIREBASE_APIKEY=...

dotnet test test/BlazorApp.PlaywrightTests/BlazorApp.PlaywrightTests.csproj
```

## Container images

```bash
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```
