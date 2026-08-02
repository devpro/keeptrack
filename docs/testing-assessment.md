# Testing solution assessment

This document assesses the state of Keeptrack's automated test suite as of 2026-07-27.
It inventories what exists, judges how well each layer is covered, and lists the user walkthroughs that currently have **no** end-to-end coverage.
It complements `docs/code-quality-findings.md` (which tracks specific defects) and `docs/playwright-e2e-tests-plan.md` (the original e2e design), rather than duplicating them.

## Summary

The suite is strong and layered, with roughly 376 test methods across four projects.
The API (WebApi) is very well covered at both the unit and integration levels; the Domain services are uniformly unit-tested;
the Blazor UI is covered by a Playwright smoke suite that proves every page loads and that each trackable type's core add/edit/delete/link journey works.

The main gaps are all in the **UI (Playwright) layer**, and all in flows that already have API-level coverage but no browser-level proof:
the three bulk-import pages, the account-management page, the user-preferences UI, the full reference-data admin page, and most of the Quick Add type variants.
The **Blazor unit layer is thin** (9 tests) — most component logic is only exercised transitively through Playwright, which is slower and gated behind `E2E_ENABLED`.

## Test topology

| Project                          | Kind                                                      | Runner                                | Count | Needs                                       |
|----------------------------------|-----------------------------------------------------------|---------------------------------------|-------|---------------------------------------------|
| `test/WebApi.UnitTests`          | Unit (pure logic, mocked repos, stub HTTP handlers)       | xunit v3 / Microsoft.Testing.Platform | ~211  | nothing external                            |
| `test/WebApi.IntegrationTests`   | Integration (real Kestrel + real MongoDB + Firebase auth) | xunit v3                              | ~121  | MongoDB, Firebase test user                 |
| `test/BlazorApp.UnitTests`       | Unit (component/helper logic)                             | xunit v3                              | ~9    | nothing external                            |
| `test/BlazorApp.PlaywrightTests` | End-to-end (real browser, both hosts in-process)          | Playwright + xunit v3                 | ~35   | `E2E_ENABLED=true`, browsers, provider keys |
| `test/Testing.Shared`            | Shared hosting/auth infrastructure (not a test project)   | —                                     | —     | —                                           |

Coverage is collected in CI via `dotnet test --coverage --coverage-output-format cobertura` and reported to SonarCloud (`.github/workflows/ci.yaml`).
There is no enforced per-project coverage threshold gate in the pipeline; SonarCloud tracks the trend but a drop does not by itself fail the build.

## What is well covered

**Domain services — uniformly unit-tested.**
Every service in `src/Domain/Services` has a matching test:
`WatchNextService`, `WishlistService`, `CarMetricsService`, `HouseMetricsService`, `HealthMetricsService`, `AmazonOrderPreviewService`, `AmazonImportMergeService`, `OwnedItemImportMergeService`, `GenericVideoGameImportService`.
These are pure computation classes, and the tests exercise the tricky branches (next-episode confirmation, the reimbursement balance tolerance, the import merge/dedup engine, the PSN bundled-transaction disambiguation).

**Reference-data enrichment — deep unit and integration coverage.**
`ReferenceEnrichmentServiceTest`, `ReferenceSyncServiceTest`, `ExternalProviderResilienceTest`, and per-provider client tests (`GoogleBooksClientTest`, `OpenLibraryClientTest`, `BnfClientTest`) cover parsing and resolution against stubbed
HTTP.
Integration tests (`TvShowReferenceRepositoryTest`, `BookReferenceRepositoryTest`, `AlbumReferenceRepositoryTest`, `VideoGameReferenceRepositoryTest`, `PersonReferenceRepositoryTest`, `TvShowReferenceLinkingTest`,
`RefreshReferenceResourceTest`, `UnlinkReferenceResourceTest`, `BookProviderSearchAndLinkResourceTest`, `BookUnresolvedQueueTest`, `ReferenceDataExportImportTest`, `ReferenceDataAdminResourceTest`) prove the real MongoDB
serialization/alias/dedup behavior that a mock cannot.

**TV Time import — parser-level and end-to-end (API).**
Every CSV parser under `Import/Parsers` has a dedicated test, plus `TvTimeImportServiceIdempotencyTest` (re-import safety) and `TvTimeImportResourceTest` (full API upload/poll cycle).

**API CRUD — one resource test per type.**
Each trackable type has a full create/read/update/delete integration test (`BookResourceTest`, `MovieResourceTest`, `AlbumResourceTest`, `TvShowResourceTest`, `VideoGameResourceTest`, `CarResourceTest`/`CarHistoryResourceTest`,
`HouseResourceTest`/`HouseHistoryResourceTest`, `HealthProfileResourceTest`/`HealthRecordResourceTest`, `PlaylistResourceTest`/`SongResourceTest`, `CollectibleResourceTest`, `GearResourceTest`).
Cross-cutting API concerns are covered too: `FreeTierTest` (quota + policy reflection guard), `ApiExceptionFilterAttributeTest`, `MongoDbHealthCheckTest`, `JobStoreTest`, `LeaseRepositoryTest`, `BackgroundJobRepositoryTest`,
`ListSortingRepositoryTest`, `StatsResourceTest`, `SystemStatusResourceTest`, `WishlistShareResourceTest`, `UserPreferencesResourceTest`.

**UI happy paths — one Playwright smoke test per type.**
`ListStateSmokeTest` (search/filter/pagination URL persistence and back-navigation), `OwnershipSmokeTest`, `VideoGamePlatformSmokeTest`, `SharedWishlistSmokeTest` (genuinely anonymous), `WatchNextSmokeTest`, `AuthSmokeTest` (login redirect
+ logout), and per-type add/link/delete flows all exist.
`MobileScreenshotTest` provides an assertion-free phone-viewport visual-review harness.

## Coverage gaps: walkthroughs with no end-to-end (browser) test

All of these have API/integration or unit coverage but are **never driven through the actual UI**, so a broken form binding, missing DI registration, or Blazor render bug would not be caught by the automated suite (exactly the class of bug
the memory note "build/tests don't catch DI/UI bugs here" warns about).

| #  | Walkthrough                                                                                              | UI page                                           | API/unit coverage today                                                                      | E2E gap                                                                                                                                                                                                                                                                                                                                                       |
|----|----------------------------------------------------------------------------------------------------------|---------------------------------------------------|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | ~~**TV Time import**~~ (upload zip → poll job → see results)                                             | `Import/ImportPage.razor`                         | `TvTimeImportResourceTest` + all parsers                                                     | **Closed** — `TvTimeImportSmokeTest` drives the upload/progress/result UI                                                                                                                                                                                                                                                                                     |
| 2  | ~~**Amazon order import**~~ (upload CSV → preview → commit)                                              | `Import/AmazonImportPage.razor`                   | `AmazonImportResourceTest`, service tests                                                    | **Closed** — `AmazonImportSmokeTest` drives upload/preview/commit/result                                                                                                                                                                                                                                                                                      |
| 3  | ~~**Generic video-game import**~~ (PSN-style CSV → preview → commit)                                     | `Import/GenericVideoGameImportPage.razor`         | `GenericVideoGameImportResourceTest`, service test                                           | **Closed** — `GenericVideoGameImportSmokeTest` drives upload/preview/commit/result                                                                                                                                                                                                                                                                            |
| 4  | ~~**Account management**~~ (view identity)                                                               | `Account/Pages/Manage.razor`                      | none                                                                                         | **Closed** — `ManageAccountSmokeTest` asserts the signed-in identity renders                                                                                                                                                                                                                                                                                  |
| 5  | ~~**User preferences**~~ (edit and persist settings)                                                     | `Account/Pages/Manage.razor`                      | `UserPreferencesResourceTest`                                                                | **Closed** — `ManageAccountSmokeTest` round-trips a preference toggle through the UI (toggle → persisted → reload reflects it)                                                                                                                                                                                                                                |
| 6  | **Reference-data admin page** (search, unresolved queue, provider picker, link, sync-now, export/import) | `ReferenceDataAdmin/ReferenceDataAdminPage.razor` | `ReferenceDataAdminResourceTest`, `BookUnresolvedQueueTest`, `ReferenceDataExportImportTest` | **Partially closed** — `ReferenceDataAdminSmokeTest` drives page load, the System panel, unresolved type-switching, and the export→import round-trip. The provider search/link flow is left to the per-type detail-page smoke tests (same endpoints, real providers), and a full sync-now poll is deliberately not driven (flakes on provider latency).       |
| 7  | ~~**Quick Add — most types**~~                                                                           | `QuickAdd/QuickAddPage.razor`                     | per-type resource tests                                                                      | **Not a real gap** — `QuickAddSmokeTest` deliberately covers one media type (movie) and one record type (car), which exercise Quick Add's whole plumbing; the per-type form fields are already covered by each type's own detail-page smoke test, so per-type Quick Add scenarios would be duplication the quality bar rejects. Left intentionally uncovered. |
| 8  | **Playlist song editing** (add/edit/remove songs within a playlist)                                      | `Inventory/Pages/PlaylistDetail.razor`            | `SongResourceTest`, `PlaylistResourceTest`                                                   | `PlaylistSmokeTest` covers add/delete of the playlist itself, not the embedded song-editing UI                                                                                                                                                                                                                                                                |
| 9  | **Car/House/Health history rows** (add/edit history entries and see computed metrics/charts)             | `CarDetail`, `HouseDetail`, `HealthProfileDetail` | metrics service unit tests + history resource tests                                          | Smoke tests create the parent and (for Health) one record; the metrics charts and multi-row history editing are not asserted in the browser                                                                                                                                                                                                                   |
| 10 | **Error / NotFound pages**                                                                               | `Pages/Error.razor`, `Pages/NotFound.razor`       | none                                                                                         | No test asserts the error or 404 experience                                                                                                                                                                                                                                                                                                                   |

## Secondary observations

- **Blazor unit layer is under-invested.**
  Only `ReturnUrlResolverTest` and `DateOnlyInputTest` exist.
  Component logic that is pure enough to test cheaply (form state transitions, the owned-versions draft/save flow, filter URL round-tripping) is currently only proven through Playwright, which is slower, gated, and heavier to debug.
  Moving some of that down to bUnit-style component tests would tighten the feedback loop.

- **E2E provider dependence.**
  Several smoke tests (Movie/TvShow/VideoGame/Album linking) hit real TMDB/RAWG/Discogs and hard-require API keys; only the Google Books path uses a deterministic synthetic seed.
  This is a deliberate trade-off (documented in the plan), but it means those tests cannot run in a keyless CI job and can flake on provider latency.

- **No enforced coverage gate.**
  Coverage is measured and sent to SonarCloud but nothing fails the build on a regression.
  If the quality bar warrants it, a minimum-coverage gate on the WebApi projects would make the "every non-trivial piece of logic needs a test" rule mechanically enforced rather than review-dependent.

- **Import parsers are the best-tested area; import *UI* is the least-tested.**
  The asymmetry is worth closing since imports are exactly the flows where a user uploads a large real file once and cannot easily retry — a broken progress/preview screen is high-impact and currently invisible to CI.

## Recommendations (priority order)

1. ~~Add a Playwright smoke test for each of the three import pages~~ — **Done and verified** (2026-07-27): `AmazonImportSmokeTest`, `GenericVideoGameImportSmokeTest`, `TvTimeImportSmokeTest`, each uploading a small GUID-suffixed in-memory
   fixture (`Support/*FixtureCsvBuilder`/`*FixtureZipBuilder`) through the real UI and cleaning up via the API.
   All three pass in self-hosted mutating mode (`E2E_ENABLED=true`, Firebase account as `E2E_USERNAME`, provider keys from `appsettings.Development.json`).
2. ~~Add an E2E test that opens `ReferenceDataAdminPage` end-to-end~~ — **Done and verified** (2026-07-27): `ReferenceDataAdminSmokeTest` covers page load + System panel + unresolved type-switch + export→import round-trip (the
   provider-free, deterministic surfaces).
   Provider search/link stays with the detail-page smoke tests; sync-now polling is left out as known-flaky.
3. ~~Extend `QuickAddSmokeTest` to cover the remaining Quick Add types~~ — **Withdrawn** (2026-07-27): on review, `QuickAddSmokeTest` intentionally proves Quick Add's plumbing with one media + one record type, and the per-type fields are
   covered by each type's own detail-page smoke test.
   Adding per-type Quick Add scenarios would duplicate existing coverage, which the quality bar rejects.
4. ~~Add a minimal smoke test for `Manage.razor` and the user-preferences UI~~ — **Done and verified** (2026-07-27): `ManageAccountSmokeTest` covers the account identity and a preference-toggle UI round-trip (persistence confirmed, then
   restored via the API so the shared account is unchanged).
   Closes gaps #4 and #5.
5. Introduce a small bUnit component-test project to move fast-feedback UI logic off the gated Playwright suite.
6. Add a cheap smoke test for the Error / NotFound pages.
7. Consider a coverage-threshold gate on the WebApi projects in CI.
