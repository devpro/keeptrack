# Playwright end-to-end tests plan

## Goal

Add browser-level end-to-end (e2e) smoke tests that prove every page loads and the core user journeys work: sign in, browse every list page, add a book, link it to reference data, delete it.
The suite must run three ways from the same code: in-process against `Program` (local dev and CI), against an already-running local instance, and against a real deployed platform.
Minimal code is a hard requirement: plain xunit facts, one generic page object for all ten identical list pages, no Gherkin, no aspect framework.
Every knob is an environment variable, and a test run must be debuggable in Rider with breakpoints in both the tests and the application source.

## What the todo-blazor review found

`C:\Users\bthom\projects\todo-blazor\test\BlazorApp.PlaywrightTests` contains two parallel styles: Reqnroll (Gherkin features + step classes + hooks) and plain xunit smoke tests built on `Microsoft.Playwright.Xunit.v3`'s `PageTest`.
The verdict per practice:

Practice                                                            | Verdict | Reason
--------------------------------------------------------------------|---------|-------
`PageTest` base (`Microsoft.Playwright.Xunit.v3`) + plain facts     | Keep    | The package owns the browser/context/page lifecycle; tests stay ordinary debuggable xunit methods
Page objects with locators/actions sections and `WaitForReadyAsync` | Keep    | Readable and chainable (each action returns the next typed page); waiting is centralized so tests never sleep
`KestrelWebAppFactory<Program>` in-process hosting                  | Keep    | Keeptrack already has its own copy in `WebApi.IntegrationTests`; it gets extracted and reused, not duplicated
Reqnroll/Gherkin (features, steps, hooks, context keys)             | Drop    | Doubles the code for the same coverage; the smoke scenarios read fine as plain C# methods
Metalama `ScreenshotOnFailure` aspect                               | Drop    | xunit v3's `TestContext.Current.TestState` enables the same capture in `DisposeAsync` with no aspect framework
`data-testid` on almost every element                               | Soften  | Prefer role/label locators; add `data-testid` only where Bootstrap markup is genuinely ambiguous

## Keeptrack-specific constraints the design must handle

- Two hosts: the Blazor Server app and the Web API are separate processes, so "in-process" mode means two `WebApplicationFactory` instances, with the Blazor host's `WebApi:BaseUrl` pointed at the API host's dynamic address.
- The login page is OAuth-popup-only (GitHub/Google via the Firebase JS SDK), which Playwright cannot automate reliably.
- `POST /auth/callback` accepts any verified Firebase ID token, so authentication is programmatic.
  Sign in over Firebase REST `signInWithPassword` (the existing `AccountRepository` flow), post the token to `/auth/callback`, and capture the cookie as Playwright storage state.
- Admin provisioning: the `role: admin` custom claim is set with the Firebase Admin SDK.
  The Blazor host already requires `Firebase:ServiceAccount`, so the e2e harness can create/claim/delete its own ephemeral user with no new secrets.
- Reference enrichment on create fires real provider calls; hosted mode simply provides no provider keys, so new items stay unresolved and no external network flakiness enters the suite.
- The deterministic "look for a ref" path is `POST /api/reference-data/import` (covers all six reference collections) followed by the user-facing "check for reference match" button, which only queries MongoDB and never calls a provider.
- Blazor Server prerenders before the circuit connects, so page objects must wait for an interactive signal (e.g. the loading state resolving into rows), never just static markup, and never `NetworkIdle` (the circuit websocket defeats it).

## Project layout

New projects, following the existing naming and conventions (xunit v3, `Microsoft.Testing.Platform` runner, central package versions):

Path                        | Content
----------------------------|--------
`test/Testing.Shared`       | `KestrelWebAppFactory<T>` (moved from `WebApi.IntegrationTests`), `AccountRepository`, `FirebaseConfiguration`; referenced by both integration and e2e projects so no logic is duplicated
`test/BlazorApp.E2eTests`   | The Playwright suite itself

Inside `test/BlazorApp.E2eTests`:

Folder      | Content
------------|--------
`Hosting/`  | `E2eFixture` (xunit v3 `[AssemblyFixture]`): boots both hosts (or targets live URLs), provisions the user, seeds data, exposes `BaseUrl` and an authenticated `ApiClient`
`Support/`  | `E2eConfiguration` (every env var in one static class), `ReferenceFixtureZipBuilder` (synthetic in-memory reference export, same spirit as `TvTimeFixtureZipBuilder`)
`Pages/`    | `PageBase`, `ListPage` (one class for all ten list pages), `BookDetailPage`, `LoginPage`, `HomePage`
`Smoke/`    | `SmokeTestBase` and the test classes

`KestrelWebAppFactory<T>` is generalized during extraction: the env-var override name (`KESTREL_WEBAPP_URL` today) and the in-memory config overrides (the `Features:IsReferenceSyncEnabled=false` pair) become constructor parameters.
`WebApi.IntegrationTests` keeps its current behavior through a thin subclass; the e2e project composes two instances (API, then Blazor with `WebApi:BaseUrl` injected).

**Gotcha:** both `src/WebApi` and `src/BlazorApp` generate a top-level `Program` class in the global namespace, so referencing both from one test project is ambiguous.
Fix: `<ProjectReference Include="..\..\src\WebApi\WebApi.csproj" Aliases="WebApiHost" />` plus `extern alias WebApiHost;`, and use `WebApiHost::Program` / `BlazorHost::Program`.
`WebApi.IntegrationTests` already references the generated `Program` directly with no extra declaration, so no `public partial class Program` is needed in either app.

Package additions to `Directory.Packages.props`: `Microsoft.Playwright` and `Microsoft.Playwright.Xunit.v3` (latest stable, kept in sync with each other).

## Execution modes

Mode        | Trigger                                | Hosting                                   | Data
------------|----------------------------------------|-------------------------------------------|-----
Integration | `E2E_ENABLED=true`, no target URL      | Both apps in-process on dynamic ports     | Ephemeral admin user created, data seeded, everything deleted at the end
Live        | `E2E_TARGET_URL` set                   | Nothing hosted; browser hits the real URL | `E2E_USERNAME`/`E2E_PASSWORD` account; seeding via `E2E_WEBAPI_URL` unless read-only
Read-only   | `E2E_READONLY=true` (implies live use) | Nothing hosted                            | No provisioning, no seeding; every mutating test self-skips

## Configuration (environment variables only)

Harness settings, all read by `E2eConfiguration` with the defaults below:

Variable                    | Default      | Purpose
----------------------------|--------------|--------
`E2E_ENABLED`               | `false`      | Master switch; when unset every e2e test self-skips so a plain solution-wide `dotnet test` stays green
`E2E_TARGET_URL`            | *(empty)*    | Live mode: base URL of an existing BlazorApp; empty means self-host both apps in-process
`E2E_WEBAPI_URL`            | *(empty)*    | Live mode: base URL of the matching WebApi, required for seeding/cleanup when not read-only
`E2E_READONLY`              | `false`      | Skips every mutating test, user creation, and seeding
`E2E_USERNAME`              | *(empty)*    | Existing account email; empty triggers ephemeral admin user creation (integration mode only)
`E2E_PASSWORD`              | *(empty)*    | Password for `E2E_USERNAME`
`E2E_HEADLESS`              | `true`       | `false` shows the browser window
`E2E_SLOWMO_MS`             | `0`          | Milliseconds of delay injected before each Playwright action
`E2E_BROWSER`               | `chromium`   | `chromium`, `firefox` or `webkit`
`E2E_TRACE`                 | `on-failure` | `off`, `on` or `on-failure`; traces and failure screenshots land in the test output directory

Pass-through application settings (hosted mode reuses exactly the variables the integration tests already document in `CONTRIBUTING.md`):

- `Infrastructure__MongoDB__ConnectionString` / `Infrastructure__MongoDB__DatabaseName`, pointed at a dedicated database (e.g. `keeptrack_e2e`), never the dev one.
- `Authentication__JwtBearer__Authority` / `__TokenValidation__Issuer` / `__TokenValidation__Audience` for the hosted API.
- `FIREBASE_APIKEY` for the REST sign-in (same variable the integration tests use).
- `Firebase__ServiceAccount` and `Firebase__WebAppConfiguration__ApiKey`/`AuthDomain`/`ProjectId` for the hosted Blazor app and the Admin SDK.
- No provider keys (`Tmdb__ApiKey`, `Rawg__ApiKey`, `Discogs__Token`) on purpose; the app degrades gracefully and the suite stays deterministic.

## Authentication and provisioning flow

1. `E2eFixture` starts (once per run, xunit v3 assembly fixture) and resolves the mode from the variables above; if `E2E_ENABLED` is unset it marks the run skipped and every test short-circuits.
2. Integration mode with no `E2E_USERNAME`: create `e2e-<guid>@keeptrack.test` with a random password via `FirebaseAuth.CreateUserAsync`, then `SetCustomUserClaimsAsync(uid, { role: "admin" })`.
3. Sign in over Firebase REST (`AccountRepository.AuthenticateAsync` from `Testing.Shared`) to get an ID token; keep the bearer token for direct WebApi seeding calls.
4. Create a Playwright `APIRequestContext` on the Blazor base URL, `POST /auth/callback` with the ID token, and save `StorageStateAsync()` to a file.
5. `SmokeTestBase` overrides `PageTest.ContextOptions()` to supply `StorageStatePath`, `BaseURL`, viewport and `IgnoreHTTPSErrors`, so every test starts already signed in; only the dedicated auth test uses a clean context.
6. Seeding (integration mode): import the synthetic reference fixture via `POST /api/reference-data/import`, then create a handful of items per type via the REST API using the shared `WebApi.Contracts` DTOs.
7. Teardown: delete the seeded documents via the API, then delete the ephemeral Firebase user; live mode tests clean up whatever they created, same discipline as the resource tests.

## Page objects

- `PageBase(IPage page)`: sidebar navigation locators, `WaitForReadyAsync()` (page title + a per-page interactive signal), typed `Open<X>Async()` helpers that return the next page object.
- `ListPage`: one class parameterized by route, title and item name, because `InventoryList` renders all ten list pages identically.
  It covers search, paging, the add form (fill by `GetByLabel`), row lookup by text, inline edit, and delete confirmation.
- `BookDetailPage` first; other detail pages are added only when a test needs them.
- Locator strategy: `GetByRole`/`GetByLabel` first; add a `data-testid` to `InventoryList`'s few ambiguous controls (add button, save/cancel, delete-confirm modal) only if role/name lookup proves fragile in practice.
- `WaitForReadyAsync` on list pages asserts the loading state has resolved (spinner hidden, table or empty-state visible), which also guarantees the Blazor circuit is interactive before any click.

## Smoke test scope (first iteration)

Test class            | Read-only safe | Proves
----------------------|----------------|-------
`NavigationSmokeTest` | Yes            | Home, all ten list pages, wishlist and watch-next each load with their header and no error boundary
`AuthSmokeTest`       | Yes            | An anonymous visit to `/books` lands on `/account/login`; logout ends the session
`BookSmokeTest`       | No             | Add a book through the list form, see it in the list, open its detail page, edit a field, delete it
`ReferenceSmokeTest`  | No             | With the fixture imported, add the matching book, click "check for reference match" on the detail page, assert title/author/cover resolve

Read-only mode runs only the first two classes; mutating tests call `Assert.Skip` when `E2E_READONLY=true`.
Admin page (`/admin/reference-data`) and import page (`/import`) journeys are explicitly deferred, as are the other item types' CRUD journeys (they exercise the same `InventoryList`/`DataCrudControllerBase` code paths as books).

## Failure diagnostics

- Tracing starts in `SmokeTestBase.InitializeAsync` when `E2E_TRACE` is `on` or `on-failure`.
- `DisposeAsync` checks `TestContext.Current.TestState`; on failure it saves a full-page screenshot and the trace zip, named after the test, otherwise it discards the trace.
- Trace zips open in `https://trace.playwright.dev` or via `playwright show-trace`, giving DOM snapshots and network for every failed CI run.
- CI uploads the trace/screenshot directory as a build artifact when the e2e job fails.

## Running and debugging

Local run (integration mode), after a one-time `pwsh test/BlazorApp.E2eTests/bin/Debug/net10.0/playwright.ps1 install chromium`:

```bash
export E2E_ENABLED=true
# plus the same MongoDB/Firebase variables the integration tests already need
dotnet test test/BlazorApp.E2eTests/BlazorApp.E2eTests.csproj
```

Live run against a real platform:

```bash
export E2E_ENABLED=true E2E_TARGET_URL=https://keeptrack.example.com E2E_READONLY=true
export E2E_USERNAME=... E2E_PASSWORD=... FIREBASE_APIKEY=...
dotnet test test/BlazorApp.E2eTests/BlazorApp.E2eTests.csproj
```

Rider debugging works with zero extra machinery because everything is an ordinary xunit test:

- Add the `E2E_*` variables to the existing `Local.runsettings` (Rider reads it automatically) and debug any test from the gutter.
- In integration mode both apps run inside the test process, so breakpoints hit in `BlazorApp`/`WebApi` source during a browser click, not just in test code.
- `E2E_HEADLESS=false` plus `E2E_SLOWMO_MS=250` to watch the run; `PWDEBUG=1` opens the Playwright inspector.
- To debug the app itself under Rider's debugger instead, `dotnet run` both apps, set `E2E_TARGET_URL`/`E2E_WEBAPI_URL` to them, and run the tests as the client.

## CI integration

- A new `e2e` job in `.github/workflows/ci.yaml` (and later the GitLab/Azure equivalents), `needs: git-check`, gated on `app_changed` like the code-quality job.
- Steps: checkout, .NET setup, `scripts/mongodb-install.sh`, `dotnet build` the e2e project, then `playwright.ps1 install --with-deps chromium`.
  Finally `dotnet test` with `E2E_ENABLED=true` and the same Firebase secrets the code-quality job already receives.
- Cache `~/.cache/ms-playwright` keyed on the `Microsoft.Playwright` package version to avoid re-downloading browsers every run.
- The existing code-quality job needs no change: it runs the whole solution, but the e2e tests self-skip there because `E2E_ENABLED` is unset.
- Upload traces/screenshots as an artifact on failure (see above).

## Implementation phases

1. **Foundation**: extract `Testing.Shared`, scaffold `BlazorApp.E2eTests`, `E2eConfiguration`, the dual-host `E2eFixture` with extern-alias wiring, and programmatic auth + storage state.
   This phase ends with the `E2E_ENABLED` skip guard and a single trivial "home page loads" test proving the whole chain.
2. **Smoke suite**: `PageBase`/`ListPage`/`BookDetailPage`, the four test classes above, ephemeral-user provisioning, reference fixture import, read-only skips, failure diagnostics.
3. **CI**: the `e2e` GitHub Actions job, browser caching, artifact upload; update `CONTRIBUTING.md` (new variables, `Local.runsettings` template additions) and `CLAUDE.md`'s test section.
4. **Later**: remaining item types' journeys, TV show episode checklist, wishlist/watch-next with seeded data, admin and import pages, optional Gherkin layer only if ever wanted (deliberately out of scope now).

## Open questions / accepted trade-offs

- The suite requires a real Firebase project even in CI, same as the integration tests today; a fully offline auth fake would mean forking the auth pipeline and is not worth it for smoke coverage.
- Ephemeral user creation needs the service-account secret in CI; if that is ever unacceptable, the fallback is the existing shared test user via `E2E_USERNAME`/`E2E_PASSWORD` (at the cost of parallel-run isolation).
- One browser (Chromium) is enough for smoke; `E2E_BROWSER` exists so cross-browser runs stay a config change, not a code change.
- Watch-next/wishlist pages are only asserted to load in phase 2, because meaningful content assertions need reference-linked, partially-watched seed data (phase 4).
