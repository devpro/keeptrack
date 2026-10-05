# Explore

`/explore` suggests top-rated titles the caller does not track, with one-click add and dismiss with undo, for movies, TV shows and video games.
Books and albums answer 400, having no best-of listing.
The API is `ExploreController`/`ExploreService`.

## Catalogue

**The list originates from the provider, never from the local reference collections**, which only hold titles someone already tracks.
The sources are TMDB's `/{movie,tv}/top_rated` and IGDB's `sort {rating|aggregated_rating} desc`.

**Requests read `explore_catalogue`, never the provider**: a materialized copy of each ranking, rewritten weekly by `ExploreCatalogueRefreshService`, owner-less since a ranking is a global fact.
`CatalogueDepth` (1000 per ranking) sets how far a user can scroll.

- A **ranking** is a domain plus an ordering, declared once in the injected `ExploreRankings` and derived from `RatingSourceCatalog`, so a game provider gets one ranking per supported source.
  `DisplaySource` falls back to the ranking's own number when the catalogue cannot carry a source, and a pass prunes rankings no longer maintained.
- **Refresh safety**: one `$set` per rating key (never replacing the map), pruning only after a complete pass, and staleness read from the **oldest** `refreshed_at` in a ranking.
- The refresh rides the reference sync's tick and lease on its own 7-day window, and `sync-now?exploreOnly=true` rebuilds only the rankings (`ReferenceSyncStage.RefreshingExplore`).
- **Gotcha: a plain average ranks a single-vote title above every classic**, so IGDB uses a vote floor (`MinUserRatingCount`/`MinCriticRatingCount`) as its only filter, and RAWG constrained `metacritic={MinMetacritic},100` server side.
  Never filter client side: the paging loop stops on an empty page.
- IGDB is deliberately not restricted to main games: a well-reviewed DLC or remaster is a legitimate suggestion.

## Ordering and ratings

Ordering follows the admin-selected primary rating source (see [Ratings](reference-data.md#ratings)).
Under IMDb, movies and TV keep TMDB's order and IMDb only fills the number, backfilled by the refresh from the shared OMDb budget, since partial coverage would float unrated titles up.
`app_setting.explore_use_tmdb` forces TMDB's vote and skips the backfill.

**A card links to the title's provider page in a new tab** (`ProviderUrl`/`ProviderName`), following the displayed source where possible.
URLs are stored per source (`web_urls`, merged key by key), since IGDB keys pages by slug, and `ProviderWebLinks` holds only the id-derived ones.
The IMDb link is stored even when OMDb was never called, and `FindMissingRatingOrLinkAsync` picks up an entry with a rating but no link.

## Excluding what the user tracks

**The exclusion needs both halves**, implemented once in `ExploreExclusionQueries` over `IExploreSourceRepository`:

- **by provider id**: `FindLinkedReferenceIdsAsync` then `FindExternalIdsAsync`, a projected read;
- **by title**: `FindDistinctTitlesAsync` with `NormalizeLoose`, since providers spell one work differently (`Mass Effect: Legendary Edition` and `Mass Effect Legendary Edition`, RAWG's `GoldenEye 007 (1997)`).

Both are only as good as provider adoption: a RAWG-linked reference has no `igdb` id until it is adopted, and the fix is adoption, never a workaround in Explore (see [Reference matching](reference-matching.md#adopting-the-default-providers-id)).

`explore_dismissal` is keyed `{owner_id, item_type, external_source, external_id}` on the **discovery** provider's id (`ExploreRankings.DiscoverySource`), since TMDB and RAWG ids are both plain integers.
Dismissals keep the provider they were recorded under, so switching back to a previous provider restores them (owner's call).

## Adding

**Adding goes through `POST /api/explore/{type}/add/{externalId}`**: it creates the item, then awaits `Resolve*Async` with the exact provider id, and enforces the free-tier quota through `FreeTierQuota.CheckAsync`.
The controller is plain `[Authorize]` with video games member-gated per request (`RequireAccessTo`), and the page hides that tab behind `<AuthorizeView Policy="MemberOnly">`.

## Paging

**Paging is a rank cursor (`?after=`), never skip and limit**, since per-caller exclusions apply after the ranked read.
`ExploreSuggestionPageDto` carries `NextCursor` (null when exhausted) and `CataloguePending` ("not built yet" rather than "seen everything"), and the cursor advances over every entry examined, so a short page can still have more.

`ExplorePage.razor` keeps the tab in `?tab=`, one `TabState` per tab, and appends below the current cards (`AppendNextPageAsync`, shared by "Load more" and the top-up after an add or dismiss, both through `ActAsync`).
