# Reference ratings

Provider ("reference") ratings for tracked items - the linked reference's own aggregate score (TMDB, RAWG, Metacritic, Discogs, Google Books, Open Library), shown alongside the user's personal star rating.

## Status

Phase 1 is implemented across all five reference-bearing media types (Movie, TV show, Video game, Album, Book).
Build is green; the WebApi unit suite passes (303 tests, including the new rating tests); the Movies slice also has real-MongoDB integration coverage.
The user has confirmed the feature displays well and the mechanics are right.

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
- **Primary-source selection:** a **code default per media type** *as shipped in Phase 1* - not admin-configurable and not per-user yet.
  Reason it was fine to ship this way: only video games have more than one source so far, and the storage already supports upgrading later with no migration.
  Agreed follow-up: make the primary source admin-selectable, starting with video games (RAWG vs Metacritic) since it's the one multi-source type today, built as a general per-domain setting so IMDb (phase 2) reuses it - see next-steps step 1.
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

## What to do next

1. **Admin-selectable primary source (starting with video games: RAWG vs Metacritic).** Video games are the one type that already has two sources today, so this is the first place the code-default decision is worth revisiting - ahead of, and independent of, IMDb.
  Build it **general, not games-only**: a per-domain "primary rating source" setting (config or a stored admin setting) that the enrichment's `PrimaryRating` call reads instead of the current hardcoded key.
  Keep it **admin/global, not per-user** - changing it must recompute the denormalized `ReferenceRating` scalar on every linked tenant item from the reference dict, which is one bulk `SetReferenceRatingAsync` pass per affected reference; per-user couldn't be a single bulk update.
  So it's a setting **plus** an admin "recompute reference ratings" action (on the reference-data admin page) that re-propagates when the source changes.
  Note the switch's effect: Metacritic is `/100` and often absent on RAWG, so flipping games to Metacritic-primary blanks the pill for many games and sorts them last - RAWG stays the safer default.
  This same mechanism then covers IMDb-vs-TMDB for movies/TV in Phase 2 for free.
2. **Phase 2 - IMDb ratings for movies/TV.** Add an `imdb` source to the movie/TV `Ratings` dict.
  IMDb has no public ratings API; options are OMDb (needs an API key, returns `imdbRating`/`imdbVotes`) or TMDB `external_ids` → IMDb id → a data source.
  Once movies/TV have two sources, the primary is chosen via the admin-selectable mechanism from step 1 (the storage already supports it with no migration).
3. **Phase 3 - "suggest N top-rated not-yet-added" feature.** Read a source, order the reference collection by `ratings.<source>.value` desc, skip titles the user already tracks, return the top N.
  This needs a supporting index on the chosen `ratings.<source>.value` path in `scripts/mongodb-create-index.js` (not added yet - phase 1 added no indexes because the per-owner tenant-side sort is small).
4. **Per-type integration + Playwright coverage.** Movies has real-Mongo integration coverage; add the equivalent for TV/game/album/book if desired (the logic is shared, so this is defense-in-depth, not filling a logic gap). The existing Book Playwright smoke test uses a synthetic seeded reference, so it does not exercise a real provider rating.
5. **French / non-English book ratings.** If it becomes worth it, try a second fallback source for books (e.g. a provider with better FR coverage) under the same `IBookRatingByIsbnLookup`-style pattern.
6. **Backfill existing data.** Ratings fill in on the next sync (`Sync now` on the reference-data admin page, or re-check a reference). No migration script is needed; if a bulk backfill is ever wanted it is just a forced sync, not a `scripts/*.js`.
7. **Docs.** Fold the durable parts of this into `CLAUDE.md`'s reference-data section once the feature settles (kept here as a working plan for now).
