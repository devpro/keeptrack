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
`TvShow` and `Movie` search `Title` only.
This is intentional: each entity type exposes the search behavior that fits its own fields, not a shared generic contract.

## Known gaps (not yet implemented)

These are acknowledged as incomplete rather than deliberately permanent.
Track and prioritize separately.

### Open Library's book search has the same free-text noise as Discogs had, and is deliberately left alone (decided 2026-08-05 - read this before "fixing" it)

`OpenLibraryClient.SearchByTitleAsync` queries `q=` for the same documented reason Discogs did (relevance across alternate and regional titles, which the field-scoped `title=` misses entirely), and it has the same consequence.
Confirmed against the real API while investigating the album finding above:
`q=Dune&author=Frank Herbert` returns "House Corrino" among the top hits, and `q=Sabbath` returns "Iron man" by Tony Iommi - matches on description and subject text, not on the title.
The `TitleNormalizer.LooselyContains` filter written for `DiscogsClient` would apply unchanged.

**It was deliberately not applied**, at the owner's call, and the reason is specific rather than general caution.
Book search is the one domain with a multi-provider ladder rather than a single query:
`BookReferenceClientBase` tries the ISBN alone, then title+author, then title alone, widening only on an **empty** step, across three providers with different catalogues and different failure modes.
Recent work made that ladder reliable through a full Google Books search outage (see "A book search by ISBN had no fallback when Google Books was down" above), and a filter that can empty a step changes which rung the ladder lands on,
so it is not a local change to one client the way it is for Discogs, whose search is one query with one widening retry.

If it is picked up later: the filter belongs inside each provider's own `SearchByTitleAsync`, never around `BookReferenceClientBase`'s ladder (a filtered-to-empty step must widen, not abort),
it must not touch the ISBN rung at all (an exact identifier can legitimately resolve an edition whose title text differs from what the tenant typed), and it needs coverage proving the outage-era ISBN fallback still behaves.
Google Books (`intitle:`) and BnF (`bib.title`) query title-scoped fields already, so only Open Library is affected.

### `CancellationToken` propagation is partial

Wired end to end for the generic CRUD surface: `IDataRepository<TModel>`/`MongoDbRepositoryBase`, `DataCrudControllerBase`'s five actions, `InventoryApiClientBase`, the four parent-cascade deletes,
and the Car/House/HealthProfile/TvShow metrics and suggestion actions.
`CancellationTokenPropagationTest` proves a cancelled token actually aborts a real MongoDB call.
`OnCreatedAsync` deliberately takes none: it starts detached background enrichment, which the request that started it must never cancel.

**Still open:** the custom `I<X>Repository` methods, the provider-calling services, and the Blazor API clients other than `InventoryApiClientBase`.
Most of those are reached from background work, where a request token is the wrong one, so each caller needs a case-by-case read before threading one through.

### `PageSize` has no upper bound

`PagedRequest.Page` and `PageSize` both reject zero and negative values (`PaginationBoundsResourceTest`).
`PageSize` stays uncapped because `CarDetail`, `HealthProfileDetail`, `HouseDetail`, `TvShowDetail`, `AlbumDetail` and `PlaylistDetail` request a very large page to fetch one parent's whole child collection.
A real bound needs a purpose-built "all children of this parent" endpoint first, rather than a validation attribute on the shared list shape.

### Test coverage gaps

- No test proves the `AdminOnly` policy rejects a non-admin caller over HTTP: `WebApi.IntegrationTests` has one Firebase account, which carries `role: admin`, and no Admin SDK access to mint a second one.
- `BookResourceTest` and `MovieResourceTest` are close to copy-pasted.
  A parameterized test base mirroring `DataCrudControllerBase<TDto, TModel>` would cover every resource without per-type duplication.
