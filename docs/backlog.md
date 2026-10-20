# Backlog

Known debt and gaps, not yet scheduled.

## Code quality

- [ ] Shorten the remaining code comments to the why and the gotchas, in the writing style of `AGENTS.md`, file by file when a file is touched rather than as one sweeping change:
  spaced hyphens used as dashes, measurements and stories that belong nowhere, and comments telling history ("used to", "no longer").
- [ ] Decide on the dashes and second person in UI copy (`— Choose an album —` placeholders, "Welcome back —", "across your shows"),
  which the writing rules cover for documentation but not explicitly for product text.
- [ ] Migrate the `WebApi/Import/` and `WebApi/ReferenceData/` feature folders to the layered shape:
  provider clients in their own folder, controllers in `Controllers/`, pure logic in `Domain/Services/` (`ReferenceMatchRules` and `RatingSourceCatalog` already are).

## Cancellation

- [ ] Pass `CancellationToken` through custom repository methods, provider services and most Blazor API clients, which do not yet.
  Most run in background work, where the request's token is the wrong one, so each needs checking individually.

## API

- [ ] Bound `PageSize`.
  Detail pages ask for one huge page to load all of a parent's children, so a cap needs a dedicated "all children of this parent" endpoint first.
- [ ] Return a 400 rather than a 500 for a malformed id passed as a child filter (`GET /api/episodes?TvShowId=not-an-object-id`), which no UI path reaches.
- [ ] Batch the reference-data import with `BulkWrite`: one round trip per document takes minutes where batching would take seconds, but it touches all six repositories.

## Providers

- [ ] IGDB's `multiquery` and `where id = (1,2,3)` could refresh a whole sync page in one request instead of one per game.
- [ ] IGDB's `similar_games` could power a "more like this" per item, independent of the Explore ranking.
- [ ] Books outside English often get no rating, Open Library's coverage being thin there: a second fallback source would follow the `IBookRatingByIsbnLookup` pattern.

## Tests

- [ ] Prove over HTTP that `AdminOnly` rejects a non-admin, which needs a second, non-admin Firebase test account.
- [ ] Replace the near-copy resource tests (`BookResourceTest`, `MovieResourceTest`) with a shared parameterized base covering every resource.
- [ ] Cover in the browser what only the API covers: song editing inside a playlist (`PlaylistSmokeTest` covers an empty playlist only), multi-row journal history and the metrics charts, and the error page.
- [ ] Move pure component logic (form state, the owned-version draft flow, filter URL round trips) into fast component tests, off the gated Playwright suite.
- [ ] Consider a coverage threshold on the WebApi projects, so "every non-trivial piece of logic needs a test" is enforced rather than reviewed.
- [ ] `StaleTokenRedirectSmokeTest.StaleFirebaseToken_On401_RedirectsToLogin_InsteadOfCrashingTheServerRender` failed once in a full parallel Playwright run on 2026-09-24 and passed twice alone.
  It only opens `/account/manage/shared/{id}`, so the failure is load dependent: read its trace in `e2e-diagnostics` the next time it fails before raising any timeout.

## CI

- [ ] Run `code-quality` and `image-scan` through the installed IstarCI package on a commit changing the application, and record in [CI and code quality](ci-and-quality.md) what passes.

## Dependencies

- [ ] `Microsoft.OpenApi` stays at 2.x: `Microsoft.AspNetCore.OpenApi` 10.x requires `[2.12.2, 3.0.0)` and its source generator fails to compile against 3.x, which only the net11.0 package supports.
- [ ] `SharpCompress` (pulled in by `MongoDB.Driver`) is pinned transitively at 0.50.x: 1.0 is a major version, adopted once the driver supports it.
