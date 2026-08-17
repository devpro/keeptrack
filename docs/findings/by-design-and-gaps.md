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

### No `CancellationToken` propagation

Controllers, `MongoDbRepositoryBase`, and `InventoryApiClientBase` (Blazor) do not accept or forward a `CancellationToken`.
Requests keep running server-side work after a client disconnects.
The test project already uses `TestContext.Current.CancellationToken` (xunit v3), so the pattern is known, just not applied to production code yet.

### No pagination bounds

`PagedRequest.Page` and `PagedRequest.PageSize` have no `[Range]` validation or clamping.
A negative `Page` produces a negative `Skip` value, which the MongoDB driver rejects.
A very large `PageSize` forces an unbounded fetch.

### Thin test coverage

`Book` and `Movie` have integration tests (`BookResourceTest`, `MovieResourceTest`); `Movie`'s now also covers `?search=`.
`Episode` and `TvShow` gained partial coverage as a side effect of `TvTimeImportResourceTest` (create/upsert/search paths, plus `Episode`'s `TvShowId` filter), but neither has a dedicated full CRUD test of its own yet.
`Album` and `VideoGame` gained full CRUD integration tests (`AlbumResourceTest`, `VideoGameResourceTest`) on 2026-07-07 while their controllers/repositories were touched anyway to add reference-data support, closing this finding for both.
`Car` and `CarHistory` gained full CRUD integration tests (`CarResourceTest`, `CarHistoryResourceTest`) plus dedicated unit coverage for `CarMetricsService` on 2026-07-09.
This was when the whole Car/CarHistory feature was built out (controller, Blazor pages, metrics), closing this finding for both as well.
No test asserts ownership isolation (that user A cannot read, update, or delete user B's record).
There is no test project for `BlazorApp` - `AuthenticationController`'s Firebase-custom-claim-to-cookie-claim copy (added for the admin role) has no automated coverage as a result, only manual verification.
The reference-data admin endpoints have integration coverage for the non-admin-rejected (403) path and for the underlying Mongo queries directly (`TvShowReferenceLinkingTest`).
But there's no coverage for the admin-succeeds path over HTTP end-to-end, since that needs a second Firebase test user with the `role: admin` claim pre-set (see `CONTRIBUTING.md`).
`BookResourceTest` and `MovieResourceTest` are also close to copy-pasted.
A generic/parameterized test base (mirroring `DataCrudControllerBase<TDto, TModel>` on the production side) would cover all resources without duplicating the test code per type.
