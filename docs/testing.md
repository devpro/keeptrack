# Testing

How the test suites are built and why.
How to run them, and the variables they need, is in [CONTRIBUTING.md](../CONTRIBUTING.md#tests).

## Suites

- **`test/WebApi.UnitTests`**: pure logic, mocked repositories, stubbed HTTP handlers.
- **`test/BlazorApp.UnitTests`**: pure component and helper logic.
- **`test/WebApi.IntegrationTests`**: a real Kestrel host (`KestrelWebAppFactory<Program>`) against real MongoDB and real Firebase authentication.
- **`test/BlazorApp.PlaywrightTests`**: a real browser driving both apps.
- **`test/Testing.Shared`**: hosting and Firebase infrastructure for both, not a test project.
  `KestrelWebAppFactory<TEntryPoint>` takes its environment variable name and configuration overrides as constructor parameters.

All use xunit v3 on the Microsoft.Testing.Platform runner, `AwesomeAssertions` for assertions and `Bogus` for data.
Mapper validation is compile-time (Mapperly diagnostics), not a test.

**A mocked-repository test cannot prove MongoDB semantics**: filters, collation, null storage and indexes need a real-MongoDB integration test.

## Integration tests

- `ResourceTestBase` gives typed HTTP helpers, `Authenticate()` (a real Firebase bearer) and `AuthenticatedUserId`.
- **Every fixture uses `KestrelWebAppFactory<Program>`**, which sets `Features:IsReferenceSyncEnabled` to `false` through `ConfigureAppConfiguration` (`UseSetting` does not work with a top-level-statement `Program.cs`),
  or the host fires real provider calls at startup.
- `TvTimeFixtureZipBuilder` builds a synthetic export in memory, and a real personal export is never committed.
- **A test whose subject is a live provider calls it through `GetThroughLiveProviderAsync`/`PostNoContentThroughLiveProviderAsync`**, which skip on a 502 and on nothing wider,
  as in `BookProviderSearchAndLinkResourceTest`'s `[Theory]` over several providers.
  An automatic match shows an outage only as a missing link, since the background one is fire-and-forget and a degraded Google Books answers 200 with no volume.
  The host records each match whose provider failed or answered no candidate (`AutomaticMatchFailureLog`),
  and `ReferenceMatchResourceTest` skips on it, since its cases only use titles their provider holds.
  Searching the provider again afterwards proves nothing during a partial outage, when some calls succeed.
- **A test that starts a background job must not let it do real work**: the `sync-now` tests use `ProviderlessWebAppFactory` (every provider credential blanked),
  except the opt-in `ReferenceSyncPollingResourceTest` (`REFERENCE_SYNC_POLL_ENABLED`).
- `CancellationTokenPropagationTest` proves the generic CRUD path cancels a real MongoDB call.

## End-to-end tests

`Microsoft.Playwright.Xunit.v3`'s `PageTest` with plain xunit facts, self-skipping unless `E2E_ENABLED=true`, so a solution-wide `dotnet test` stays green.
Gherkin was rejected as twice the code for the same coverage.

- `End2EndFixture` (`[AssemblyFixture]`) hosts both apps, signs in once and seeds a synthetic book reference.
- **Sign-in is programmatic**: the login page is OAuth popup only, which Playwright cannot drive, so the fixture signs in over Firebase REST and posts the ID token to `/auth/callback`, then reuses the cookie as storage state.
  Without `E2E_USERNAME`, it creates an ephemeral admin user through the Firebase Admin SDK and deletes it at the end.
- In self-hosted mode both apps run in the test process, so breakpoints in `BlazorApp` and `WebApi` are hit during a browser click.
- `Pages/PageBase` holds the nav locators and `Open<X>Async()`, `ListPage` is one class for all list pages, and detail titles share `.kt-title-input`.
  Locators are role and label first, and only a few unlabeled fields carry `data-testid`.
- **A page object waits for an interactive signal, never for static markup or `NetworkIdle`**: Blazor prerenders before the circuit connects, and the circuit's WebSocket keeps the network busy.
- `WatchNextSmokeTest` is in a `DisableParallelization` collection, and `ApiHttpClient` uses `LazyInitializer.EnsureInitialized`, since `??=` raced across classes.
- `QuickAddSmokeTest` covers one media type and one record type, which exercises the whole of Quick Add: the per-type fields are already covered by each type's own detail-page smoke test.
- **`ExploreSmokeTest` seeds `explore_catalogue` directly** (`End2EndFixture.SeedExploreCatalogueAsync`, self-hosted only), since the e2e host never runs the refresh.
  It seeds every ranking `ExploreRankings.Rankings` declares for a domain (the one read follows a stored admin setting), uses real provider ids only for the two `Add` cases (TMDB 278, IGDB 72),
  and its `[Theory]`s cover movies and video games, which differ in tab gating, ranking and id space.
- `MobileScreenshotTest` is an assertion-free visual harness behind `E2E_MOBILE_CHECK=true`, capturing every page at a phone viewport for review.

**`PageBase.WaitForReadyAsync` reloads once and re-asserts** (`ExpectWithReloadAsync`, also behind `ListPage.ExpectRowThumbnailAsync`), for two cases where waiting never helps:

- the URL changed but enhanced navigation never swapped the content;
- a list rendered before a detail page's save landed, a save the server issues over its circuit, so the browser has nothing to wait for.

The reload only runs after a failed assertion, and firing often is the signal to investigate rather than raise a timeout.

**Gotcha: a smoke test stays in the default list view**, since `ItemGridCard`'s `stretched-link` anchor has no size and Playwright refuses to click it.

### Failure evidence

**A failing test's evidence is in `test/BlazorApp.PlaywrightTests/bin/<config>/net10.0/e2e-diagnostics`**, written by `SmokeTestBase.DisposeAsync` for every context and page the test opened:
a full-page screenshot and the trace, with their paths printed in the test output.
A test needing a clean browser opens it through `SmokeTestBase.NewAnonymousPageAsync`, since a context disposed inside the test body is already closed when the capture runs.
Capturing never throws, so diagnosing a failure never replaces the failure.

## Databases

The integration and Playwright suites run against a real, long-lived MongoDB, with no throwaway database per test.

**Each suite uses its own database, never `keeptrack_dev`.**
`IntegrationTestDatabase.Name` (`keeptrack_integrationtests`) and `End2EndConfiguration.DatabaseName` (`keeptrack_e2e`) resolve it (overridable by `Infrastructure__MongoDB__DatabaseName` and `E2E_MONGODB_DATABASE` respectively),
and push it into the host configuration, since otherwise the in-process `Development` host falls back to `appsettings.Development.json`.
`TestDatabaseGuard.EnsureTestDatabaseName` refuses a name containing `dev`, `prod`, `staging` or `preprod`.
These are defaults rather than requirements, because an IDE sets test variables once for the whole solution.

## Cleanup

**Every test removes what it created, on success and on failure**, since unique indexes make yesterday's leftover fail today's run.
**Cleanup is registered at the moment of creation**, never in a per-test `try`/`finally`.

- `DatabaseTestBase`: `TrackCleanup(Func<Task>)`, `TrackDocument(collection, id)`, `TrackDocumentsWhere(collection, filter)`.
- `ResourceTestBase`: `CreateAsync` (POST plus register), `TrackResource`, `TrackResourcesMatching<TDto>`.
- `SmokeTestBase`: `TrackOpenItem`, `CreateItemAsync`, `TrackItemsMatching`.
- `DisposeAsync` **drains** the registry, since `TrackResourcesMatching` registers ids at cleanup time.
- Cleanups run under `CancellationToken.None`, since the test token is cancelled exactly on a timeout.
- **Deleting what a test did not create is forbidden**, except `ExploreSmokeTest`'s add, whose precondition is "the tenant does not hold this item" (`SmokeTestBase.RemoveItemsMatchingAsync`, full title).

**Gotcha: a delete filter that matches nothing looks exactly like one that worked.**
`Builders<TEntity>.Filter.Eq("_id", id)` with a `string` id against an `ObjectId` matches nothing, while the typed `Eq(x => x.Id, id)` works, so `TrackDocument` converts a parseable id to `ObjectId`.
Cleanup is verified with a document-count diff across a run, never by exit status.

- **Reference documents linked from a real provider title are left in place** (shared, deduplicated by provider id), while synthetic ones are always removed and use a per-test external id (`TestExternalId.New()`).
- Deleting a TV show cascades to its episodes.
- **A document with no list page is the easiest to leak**: `explore_dismissal` appears in no UI, so tests register the undo (`DELETE /api/explore/{type}/dismiss/{externalId}`) as they dismiss.
- **A reference created by the server in the background is not tracked by the test that triggered it.**
  Creating a book starts a background match (`BookController.OnCreatedAsync`), which can insert the same Google Books reference as the test's own explicit link.
  The unique index then rejects one insert and the link answers 500 before the test reaches `TrackDocument`, so that reference stays in the test database.
  A leftover Google Books id in `book_reference` therefore points at this race, and the next run tolerates it since the link reuses the document.
- `ServerDerivedDataSweep` (`[assembly: AssemblyFixture]`) empties `explore_catalogue` and `lease` after the run, never `provider_quota`, the ledger of OMDb calls really spent.
