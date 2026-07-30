# Reference ratings

Provider ("reference") ratings for tracked items - the linked reference's own aggregate score (TMDB, RAWG, Metacritic, Discogs, Google Books, Open Library), shown alongside the user's personal star rating.

## Status

Phase 1 is implemented across all five reference-bearing media types (Movie, TV show, Video game, Album, Book).
Next-step 1 (admin-selectable primary rating source) is also implemented, wired for video games as its first case - see "Admin-selectable primary source" below.
Build is green; the WebApi unit suite passes (315 tests, including the new rating and rating-source tests); the Movies slice also has real-MongoDB integration coverage.
The user has confirmed both the Phase 1 display/mechanics and the admin-selectable source switch (RAWG↔Metacritic + recompute) work in the running app.

## End goal / solution design

A rating for a tracked item can come from more than one source, so the shape is source-keyed from day one and the same design serves a future multi-source world (IMDb, Metacritic, ...) with no schema change.

### Two homes for the rating

1. **Canonical, on the shared reference document** (`*ReferenceModel.Ratings`): `Dictionary<string, ReferenceRatingModel>` keyed by source name.
  `ReferenceRatingModel` is `{ double Value; double Scale; int? Count; }`.
  `Value` is on the source's own `Scale` (TMDB 10, RAWG/Discogs/books 5, Metacritic 100) and is never normalized - a single list only mixes one source, so raw values still sort apples-to-apples.
  This is the source of truth the periodic sync refreshes, and it is what a future "suggest top-rated" feature will query and sort by (`ratings.<source>.value` is a fixed, indexable path).

2. **Denormalized scalar, on the tenant's own item** (`*Model.ReferenceRating` + `ReferenceRatingScale`, both `double?`): a copy of the *primary* source's value/scale, written on link and refresh.
  This exists purely so the list page can display and sort by the rating with no per-page join and no extra query - the whole point was that list load time must not regress.
  The list pill and the `Ref ★` sort key both read this scalar; the detail page shows the full per-source breakdown from the reference dict it already loads.

The tenant item already being per-user is what makes a future per-user "which source is primary" choice a clean change later (only the propagation would change, no migration) - see "Decisions locked" below for why it's a code default for now.

### Primary source per domain (the value denormalized onto the tenant item)

| Domain | Provider(s) → dict keys | Primary (pill + sort) | Scale |
|--------|-------------------------|-----------------------|-------|
| Movie / TV show | TMDB `vote_average` → `tmdb` | `tmdb` | 10 |
| Video game | RAWG `rating` → `rawg`, RAWG `metacritic` → `metacritic` | `rawg` | 5 |
| Album | Discogs community rating → `discogs` | `discogs` | 5 |
| Book | linking provider → its key (`googlebooks`/`openlibrary`), plus OL fallback → `openlibrary` | the single stored entry | 5 |

### Propagation and freshness

`SetReferenceLinkAsync` gained `canonicalRating`/`canonicalRatingScale` params (appended after each domain's existing canonical-* params) - it stamps the denormalized scalar on every matching *unlinked* tenant item at link time.
A new `SetReferenceRatingAsync(referenceId, rating, ratingScale)` on each repository re-propagates to every *already-linked* tenant item, called from each `Refresh*ReferenceAsync` so the copies stay current with the 24h sync.
`TryLinkExisting*`/`Unlink*` set/clear the scalar on the one tenant item directly.

**TMDB backfill gotcha (Movie/TV only):** `Refresh*ReferenceAsync` normally short-circuits via TMDB's `/changes` pre-check when nothing changed.
That guard is now `LastEnrichedAt is not null && reference.Ratings.Count > 0`, so a reference linked before ratings existed is force-fetched once to backfill its rating instead of being skipped forever.
RAWG/Discogs/book providers have no `/changes` endpoint and always full-fetch past the staleness cutoff, so they backfill for free.

### Admin-selectable primary source (per-domain, admin/global) - implemented

Which source is "primary" (the value denormalized onto the tenant item) is no longer a hardcoded per-domain constant.
It is an admin-selectable, global (not per-user) setting, wired for video games (RAWG vs Metacritic) as the first and only multi-source domain today.

- **Catalog:** `WebApi/ReferenceData/RatingSourceCatalog.cs` is the single declaration of, per `ReferenceItemType`, the selectable source keys plus the code default (`VideoGame → [rawg, metacritic]`, default `rawg`).
  Only domains with more than one source appear; movies/TV join it when they gain IMDb (phase 2) and reuse everything below unchanged.
  The `"rawg"`/`"metacritic"` string literals live here now; `ReferenceEnrichmentService.VideoGames.cs`'s build-key consts point at them so the two never drift.
- **Storage:** the choice lives in a shared `app_setting` collection - a single document (`_id: "global"`) whose `reference_rating_source` field is a domain→source map.
  This is one shared collection for every future global admin setting, deliberately not a collection per setting (`IAppSettingRepository`/`AppSettingRepository`, purpose-built like `LeaseRepository`, `$set` on just the one map entry with upsert).
  Config/env-var was rejected: it can't be changed from the admin UI without a redeploy, which defeats "admin-selectable".
- **Resolver:** `ReferenceEnrichmentService.GetPrimaryRatingSourceAsync(domain)` returns the stored override when it still names an available source, else the catalog default (an override for a source since removed from the catalog is ignored, never trusted).
  The three video-game `PrimaryRating` call sites (resolve/refresh/link) read this instead of the old `"rawg"` const; the other four domains still pass their single source directly (they migrate when they become multi-source).
- **Recompute:** changing the source only affects new links/syncs until the admin runs `RecomputeReferenceRatingsAsync(domain)` - one bulk `SetReferenceRatingAsync` pass over the (small, shared) reference collection re-stamping the denormalized scalar from each doc's `Ratings` dict, no provider calls.
  It runs synchronously (unlike "Sync now", which is a background job only because it hits providers) and returns `(ReferencesChecked, ItemsUpdated)`.
  The loop is a domain-agnostic generic helper, so adding movies/TV/albums later is a one-line switch arm, never a copied loop.
- **Endpoints (admin-only, on `ReferenceDataAdminController`):** `GET /api/reference-data/rating-sources`, `PUT /api/reference-data/rating-sources/{domain}` (validates source ∈ available, 400 otherwise), `POST /api/reference-data/rating-sources/{domain}/recompute`.
- **UI:** a "Primary rating source" card on the reference-data admin page - per selectable domain, a source button-group plus a **separate** Recompute button (two deliberate actions, not one) showing the checked/updated counts.
  It spells out the Metacritic caveat: `/100` and often absent on RAWG, so switching to it blanks the pill for many games and sorts them last.

### Book cross-provider rating fallback

Google Books (the default book provider) **no longer serves ratings at all** (confirmed against the live API - `averageRating` is absent even for The Hobbit / Harry Potter).
So a small cross-provider fallback was added: when a book resolves via a provider that returns no rating but does have a clean, resolved ISBN, one Open Library call (`search.json?q=isbn:{isbn}`, first result) supplies a rating, stored under the `openlibrary` source key.
It is skipped when a rating already exists, when the linking provider *is* Open Library, or when there is no ISBN.
It lives behind a dedicated one-method `IBookRatingByIsbnLookup` interface (implemented only by `OpenLibraryClient`) so the provider-agnostic `IBookReferenceClient` stays clean.

### UI

- List + grid rows: a compact bare `★ 7.8` pill in the shared per-type meta row (`*MetaRow.razor`), rendered nothing when there is no rating. Class `kt-ref-rating` in `app.css`.
- Detail pages: a per-source breakdown via the shared `ReferenceRatings.razor` component (`★ 8.2 / 10 TMDB (24,183)`), driven off the reference `Ratings` dict, so phase 2 sources appear automatically.
- Sort: a `Ref ★` option (kept short so it fits the narrow, mobile-sized sort control) added via `InventoryList`'s `HasReferenceRatingSort` flag and `ListSort.ReferenceRating`. Best-first, unrated last, a plain indexed sort on the tenant collection.

## Decisions locked (with the user)

- **Display:** bare number with a star (`★ 7.8`) in list/grid, no scale; fuller `value / scale source (count)` on the detail page.
- **Sort label:** `Ref ★` (short, mobile).
- **Primary-source selection:** shipped in Phase 1 as a **code default per media type**; now **admin-selectable and global** (not per-user), wired for video games (RAWG vs Metacritic) - see "Admin-selectable primary source" above.
  The code default is still the fallback when an admin hasn't chosen; per-user was ruled out because a switch must be a single bulk `SetReferenceRatingAsync` recompute per reference, which per-user couldn't be.
- **Video games:** RAWG's 0-5 user score is the primary (usually present); Metacritic is stored as a second source and shown on the detail page but does not drive the pill/sort (frequently absent).

## Known limitations

- **Google Books serves no ratings** - covered by the Open Library ISBN fallback above.
- **French (and other non-English) books often get no rating** - Open Library's rating coverage is thin outside English, and the ISBN must map to a work OL actually has ratings on. Confirmed by the user (English "Psion" got a rating, French titles did not). Accepted for now.
- **BnF books with no ISBN** get no rating (no lookup key) - expected edge.
- **Metacritic** is often absent on RAWG for smaller/older games.
- Non-TMDB providers have no cheap "has this changed" pre-check, so their `*Updated` sync counts always equal their `*Checked` counts (pre-existing behavior, unchanged).

## Tests added

- `ReferenceEnrichmentServiceTest` (unit, mocked): rating populate + primary-scalar propagation; no-rating-when-no-votes; TMDB backfill-forces-a-fetch; no-change short-circuit stays for an already-rated reference; TryLink sets the denormalized rating; the Open Library ISBN fallback fires for a non-OL provider and is skipped when the provider is OL.
- `MovieReferenceRatingRepositoryTest` (integration, real MongoDB): the `ReferenceRating` sort ordering (unrated last), `SetReferenceLinkAsync` stamps only unlinked matches, `SetReferenceRatingAsync` re-propagates to every already-linked item, and the `Ratings` dict round-trips through BSON.
- The other four types reuse the identical shared sort/propagation code the Movie tests cover; per-type integration tests were deliberately deferred (see next steps).
- `RatingSourceCatalogTest` (unit): video games offer RAWG+Metacritic with RAWG default; single-source domains are not yet selectable.
- `ReferenceEnrichmentServiceTest` (unit, mocked) gained: the source resolver (default / valid override / invalid-override-falls-back-to-default); `ResolveVideoGameAsync` denormalizes Metacritic's `/100` when it's the selected source; `RecomputeReferenceRatingsAsync` re-stamps every linked item with the selected source's value+scale, uses the default when unset, and throws for a non-selectable domain.

## What to do next

1. **~~Admin-selectable primary source (video games: RAWG vs Metacritic).~~ Done** - implemented as a general per-domain, admin/global setting in the shared `app_setting` collection plus a recompute action, wired for video games.
  See "Admin-selectable primary source (per-domain, admin/global) - implemented" above for the full shape.
  The same mechanism covers IMDb-vs-TMDB for movies/TV in Phase 2 for free (just add a `RatingSourceCatalog` entry and route those `PrimaryRating` call sites through `GetPrimaryRatingSourceAsync`).
2. **Phase 2 - IMDb ratings for movies/TV.** Add an `imdb` source to the movie/TV `Ratings` dict.
  IMDb has no public ratings API; options are OMDb (needs an API key, returns `imdbRating`/`imdbVotes`) or TMDB `external_ids` → IMDb id → a data source.
  Once movies/TV have two sources, the primary is chosen via the admin-selectable mechanism from step 1 (the storage already supports it with no migration).
3. **Phase 3 - "suggest N top-rated not-yet-added" feature.** Read a source, order the reference collection by `ratings.<source>.value` desc, skip titles the user already tracks, return the top N.
  This needs a supporting index on the chosen `ratings.<source>.value` path in `scripts/mongodb-create-index.js` (not added yet - phase 1 added no indexes because the per-owner tenant-side sort is small).
4. **Per-type integration + Playwright coverage.** Movies has real-Mongo integration coverage; add the equivalent for TV/game/album/book if desired (the logic is shared, so this is defense-in-depth, not filling a logic gap). The existing Book Playwright smoke test uses a synthetic seeded reference, so it does not exercise a real provider rating.
5. **French / non-English book ratings.** If it becomes worth it, try a second fallback source for books (e.g. a provider with better FR coverage) under the same `IBookRatingByIsbnLookup`-style pattern.
6. **Backfill existing data.** Ratings fill in on the next sync (`Sync now` on the reference-data admin page, or re-check a reference). No migration script is needed; if a bulk backfill is ever wanted it is just a forced sync, not a `scripts/*.js`.
7. **Docs.** Fold the durable parts of this into `CLAUDE.md`'s reference-data section once the feature settles (kept here as a working plan for now).
