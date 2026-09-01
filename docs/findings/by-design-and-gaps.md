# By design, and known gaps

Nothing here is a bug to fix.
The first section records behaviour reviewed with the owner and confirmed intentional, so a later review does not re-report it.
The second records acknowledged incompleteness, tracked and prioritized separately.

## Confirmed by design

These were reviewed with the project owner and are intentional.
No action needed.

### Each entity searches its own fields

`Book` searches `Title` + `Series` + `Author`.
`VideoGame` adds exact-match filters on `Platform` and `State`.
`TvShow` and `Movie` (once fixed) search `Title` only.
This is intentional: each entity type exposes the search behavior that fits its own fields, not a shared generic contract.

## Known gaps (not yet implemented)

These are acknowledged as incomplete rather than deliberately permanent.
Track and prioritize separately.

### Open Library's book search has the same free-text noise as Discogs had, and is deliberately left alone (decided 2026-08-05 - read this before "fixing" it)

`OpenLibraryClient.SearchByTitleAsync` queries `q=` for the same documented reason Discogs did (relevance across alternate and regional titles, which the field-scoped `title=` misses entirely - see the method's own remarks), and it has the same consequence.
Confirmed against the real API while investigating the album finding above: `q=Dune&author=Frank Herbert` returns "House Corrino" among the top hits, and `q=Sabbath` returns "Iron man" by Tony Iommi - matches on description and subject text, not on the title.
The `TitleNormalizer.LooselyContains` filter written for `DiscogsClient` would apply unchanged.

**It was deliberately not applied**, at the owner's call, and the reason is specific rather than general caution.
Book search is the one domain with a multi-provider ladder rather than a single query: `BookReferenceClientBase` tries the ISBN alone, then title+author, then title alone, widening only on an **empty** step, across three providers with different catalogues and different failure modes.
Recent work made that ladder reliable through a full Google Books search outage (see "A book search by ISBN had no fallback when Google Books was down" above), and a filter that can empty a step changes which rung the ladder lands on - so it is not a local change to one client the way it is for Discogs, whose search is one query with one widening retry.

If it is picked up later: the filter belongs inside each provider's own `SearchByTitleAsync`, never around `BookReferenceClientBase`'s ladder (a filtered-to-empty step must widen, not abort), it must not touch the ISBN rung at all (an exact identifier can legitimately resolve an edition whose title text differs from what the tenant typed), and it needs coverage proving the outage-era ISBN fallback still behaves.
Google Books (`intitle:`) and BnF (`bib.title`) query title-scoped fields already, so only Open Library is affected.

### No `CancellationToken` propagation (partially closed 2026-08-31)

The three surfaces this finding named are now wired: `IDataRepository<TModel>` and `MongoDbRepositoryBase` accept a trailing `cancellationToken = default` on every method and forward it into the underlying Mongo driver call, `DataCrudControllerBase`'s five actions (`Get`/`GetById`/`Post`/`Put`/`Delete`) take a `CancellationToken` action parameter (ASP.NET Core binds it to `HttpContext.RequestAborted` automatically) and forward it through, and `InventoryApiClientBase` (Blazor) does the same into its `HttpClient` calls.
The four parent-cascade delete methods (`CarHistory`/`Episode`/`HouseHistory`/`HealthRecord`'s `DeleteAllFor*Async`) and the `CarHistory`/`Car`/`House`/`HealthProfile` controllers' own `GetMetrics`/`GetFuelCategories`/reference-link actions were threaded through too, since they run inline in the same request.
`OnCreatedAsync` deliberately still takes no token: its overrides start detached background enrichment (own DI scope, never awaited inline, see AGENTS.md's reference-resolution section), and cancelling the HTTP request that kicked it off must never cancel that background work.
`CancellationTokenPropagationTest` proves the wiring is not just plumbing that compiles: an already-cancelled token passed into `IMovieRepository.FindOneAsync`/`FindAllAsync` throws `OperationCanceledException` against real MongoDB, movies standing in for the whole base class again.

**Still open:** the ~100 other custom methods on `I<X>Repository` interfaces (`SetReferenceLinkAsync`, `FindByIdsAsync`, the reference/rating/staleness queries, etc.) and the Domain Services that call third-party providers (`ReferenceEnrichmentService`, the sync/Explore background passes) do not take a token yet.
Most of those are reached from detached background work anyway (background jobs, `ReferenceSyncBackgroundService`, fire-and-forget resolution), where a per-request token would be the wrong one to use regardless, so threading these needs a case-by-case read of which caller is actually synchronous before extending further.
The other ~33 Blazor API clients beyond `InventoryApiClientBase` were not touched in this pass.

### No pagination bounds (`Page` closed 2026-08-31, `PageSize` upper bound is by design)

`PagedRequest.Page` now carries `[Range(1, int.MaxValue)]`, answering a deliberate 400 instead of what used
to be an accidental one: a negative or zero `Page` produced a negative Mongo `Skip`, which the driver
rejected with an `ArgumentOutOfRangeException` that `ApiExceptionFilterAttribute` happened to map to 400
because it derives from `ArgumentException`, with the driver's own internal message as the body.

`PageSize` was going to get the same treatment (capped at 100), and that broke real production traffic:
`CarDetail`/`HealthProfileDetail`/`HouseDetail` request `pageSize=int.MaxValue` to fetch a single parent's
whole child collection (CarHistory/HealthRecord/HouseHistory) in one page, and
`TvShowDetail`/`AlbumDetail`/`PlaylistDetail` use 5000 for the same "fetch everything for this one parent"
reason (see AGENTS.md's "Child entities" section).
`PageSize` therefore keeps `[Range(1, int.MaxValue)]` too (only its zero/negative end is now rejected), and
a real upper bound stays an open gap: the browse-list endpoint and the "give me this whole parent's
children" pattern share the same `pageSize` parameter today, so capping it needs a second, purpose-built
shape rather than a blanket validation attribute.
`PaginationBoundsResourceTest` covers both the rejected end and the very-large-but-legitimate end.

### Thin test coverage

`Book` and `Movie` have integration tests (`BookResourceTest`, `MovieResourceTest`); `Movie`'s now also covers `?search=`.
`Album` and `VideoGame` gained full CRUD integration tests (`AlbumResourceTest`, `VideoGameResourceTest`) on 2026-07-07 while their controllers/repositories were touched anyway to add reference-data support, closing this finding for both.
`Car` and `CarHistory` gained full CRUD integration tests (`CarResourceTest`, `CarHistoryResourceTest`) plus dedicated unit coverage for `CarMetricsService` on 2026-07-09.
This was when the whole Car/CarHistory feature was built out (controller, Blazor pages, metrics), closing this finding for both as well.
`Episode` and `TvShow` gained their own dedicated full CRUD tests (`EpisodeResourceTest`, extensions to `TvShowResourceTest`) on 2026-08-27, closing this finding for both, layered on top of the coverage `TvTimeImportResourceTest` already gave their create/upsert/search paths.
Ownership isolation (that user A cannot read, update or delete user B's record) is now covered by `OwnershipIsolationResourceTest`, added 2026-08-31: movies stand in for the whole base class, the other owner's document seeded directly through the repository since HTTP has no way to authenticate as a second account.
`BlazorApp.UnitTests` now exists, and the claim-building itself (`FirebaseClaimsBuilder`, extracted out of `AuthenticationController` as a pure function on 2026-08-31) has its own unit tests.
`AuthSmokeTest` (added 2026-08-31) now covers `/auth/callback` answering 400 for a missing token and 401 for an invalid one, and `/auth/refresh` answering 401 when the caller is not signed in, over a direct POST rather than a page navigation.
Cookie issuance itself is exercised indirectly on every e2e run, since `End2EndFixture`'s own sign-in setup posts a real token to `/auth/callback` and every other smoke test depends on the resulting cookie carrying the right claims.
`Refresh_WithAnotherUsersValidToken_Answers401` (added 2026-09-01) now covers the identity-swap check: `End2EndFixture.GetAnotherUsersIdTokenAsync` mints a second ephemeral Firebase user on demand, the same self-hosted-only capability as `ForgeStaleTokenMemberCookie`, and is deleted alongside the run's primary ephemeral user.
Writing it surfaced a real bug in the shared test helper rather than the app: `AccountRepository.AuthenticateAsync` cached a single sign-in behind one static field regardless of which username was passed, so the second identity's sign-in silently returned the first identity's already-cached token, and the new test passed for the wrong reason (200, not 401, until the cache was keyed by username).
This gap is closed for the identity-swap check; the `WebApi.IntegrationTests`-side `AdminOnly`-rejects-non-admin gap below is unrelated and still needs a permanent second Firebase account, since that suite has no Admin SDK access to mint one on demand.
The reference-data admin endpoints have integration coverage for the non-admin-rejected (403) path against the underlying Mongo queries directly (`TvShowReferenceLinkingTest`), and the standard test account now carries the `role: admin` claim, so the admin-succeeds path is covered end-to-end over HTTP too (`ReferenceDataAdminResourceTest` and friends).
There is still no coverage of the "AdminOnly" policy actually rejecting a non-admin caller over HTTP, since that needs a second Firebase test user with no claim (see `CONTRIBUTING.md`).
`BookResourceTest` and `MovieResourceTest` are also close to copy-pasted.
A generic/parameterized test base (mirroring `DataCrudControllerBase<TDto, TModel>` on the production side) would cover all resources without duplicating the test code per type.
