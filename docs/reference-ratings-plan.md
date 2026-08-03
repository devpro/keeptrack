# Reference ratings

Provider ("reference") ratings for tracked items - the linked reference's own aggregate score (TMDB, RAWG, Metacritic, Discogs, Google Books, Open Library), shown alongside the user's personal star rating.

## Status

Phase 1 is implemented across all five reference-bearing media types (Movie, TV show, Video game, Album, Book).
Next-step 1 (admin-selectable primary rating source) is also implemented, wired for video games as its first case - see "Admin-selectable primary source" below.
Phase 2 (IMDb ratings for movies/TV, via OMDb) is also implemented - movies/TV are now the second multi-source domain and reuse the step-1 admin-selection mechanism unchanged (TMDB vs IMDb) - see "Phase 2 - IMDb ratings" below.
Build is green; the WebApi unit suite passes (326 tests, including the new IMDb/OMDb, rating, and rating-source tests); the Movies slice also has real-MongoDB integration coverage.
The user has confirmed the Phase 1 display/mechanics, the admin-selectable source switch (RAWG↔Metacritic + recompute), and Phase 2 (IMDb ratings populating across movies/TV after a "Sync now") all work in the running app.

## End goal / solution design

A rating for a tracked item can come from more than one source, so the shape is source-keyed from day one and the same design serves a future multi-source world (IMDb, Metacritic, ...) with no schema change.

### Two homes for the rating

1. **Canonical, on the shared reference document** (`*ReferenceModel.Ratings`): `Dictionary<string, ReferenceRatingModel>` keyed by source name.
  `ReferenceRatingModel` is `{ double Value; double Scale; int? Count; }`.
  `Value` is on the source's own `Scale` (TMDB 10, RAWG/Discogs/books 5, Metacritic 100) and is never normalized - a single list only mixes one source, so raw values still sort apples-to-apples.
  This is the source of truth the periodic sync refreshes, and it is what a future "suggest top-rated" feature will query and sort by (`ratings.<source>.value` is a fixed, indexable path).

2. **Denormalized scalar, on the tenant's own item** (`*Model.ReferenceRating` + `ReferenceRatingScale`, both `double?`, plus `ReferenceRatingSource`, `string?`): a copy of the *primary* source's value/scale and the name of the source it
  came from, written on link and refresh.
  This exists purely so the list page can display and sort by the rating with no per-page join and no extra query - the whole point was that list load time must not regress.
  The list pill and the `Ref ★` sort key both read this scalar; the detail page shows the full per-source breakdown from the reference dict it already loads.
  The source is what makes a stored copy self-describing: without it, an item's number claimed to be "the current primary source's" whether or not it actually was, and nothing could tell an item that had been re-stamped from one that hadn't
  (see "Recompute" below).

The tenant item already being per-user is what makes a future per-user "which source is primary" choice a clean change later (only the propagation would change, no migration) -
see "Decisions locked" below for why it's a code default for now.

### Primary source per domain (the value denormalized onto the tenant item)

Domain          | Provider(s) → dict keys                                                                    | Primary (pill + sort)            | Scale
----------------|--------------------------------------------------------------------------------------------|----------------------------------|------
Movie / TV show | TMDB `vote_average` → `tmdb`, OMDb `imdbRating` → `imdb`                                   | admin-selectable, default `tmdb` | 10
Video game      | RAWG `rating` → `rawg`, RAWG `metacritic` → `metacritic`                                   | admin-selectable, default `rawg` | 5
Album           | Discogs community rating → `discogs`                                                       | `discogs`                        | 5
Book            | linking provider → its key (`googlebooks`/`openlibrary`), plus OL fallback → `openlibrary` | the single stored entry          | 5

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
  This is one shared collection for every future global admin setting, deliberately not a collection per setting (`IAppSettingRepository`/`AppSettingRepository`, purpose-built like `LeaseRepository`, `$set` on just the one map entry with
  upsert).
  Config/env-var was rejected: it can't be changed from the admin UI without a redeploy, which defeats "admin-selectable".
- **Resolver:** `ReferenceEnrichmentService.GetPrimaryRatingSourceAsync(domain)` returns the stored override when it still names an available source, else the catalog default (an override for a source since removed from the catalog is
  ignored, never trusted).
  The three video-game `PrimaryRating` call sites (resolve/refresh/link) read this instead of the old `"rawg"` const; the other four domains still pass their single source directly (they migrate when they become multi-source).
- **Recompute:** changing the source only affects new links/syncs until the admin runs `RecomputeReferenceRatingsAsync(domain)` -
  one bulk `SetReferenceRatingAsync` pass over the (small, shared) reference collection re-stamping the denormalized scalar from each doc's `Ratings` dict, no provider calls.
  It runs synchronously (unlike "Sync now", which is a background job only because it hits providers) and returns `(ReferencesChecked, ItemsUpdated)`.
  The loop is a domain-agnostic generic helper, so adding books/albums later is a one-line switch arm, never a copied loop.
  - **It opens with a counted query and does nothing when there is nothing to do.** `CountLinkedOnOtherRatingSourceAsync(source)` asks whether any linked item is still stamped with a different source; zero means the pass returns `(0, 0)`
    without reading the reference collection at all.
    That is the ordinary case - the button sits next to the source picker and gets pressed again "just in case" - and it previously cost one `UpdateMany` per reference document, every one of them writing values that were already correct.
    (`ModifiedCount` kept the reported counts honest, so the waste was in round trips, not in the numbers.)
  - An item stamped with **no** source (linked before the field existed) counts as mismatched, so the first recompute backfills the whole domain and every later one costs a single count. No migration script.
  - Deliberately **not** a value-drift repair: a value that changed while the source stayed the same is the periodic sync's job, which re-propagates through the same `SetReferenceRatingAsync`.
  - The source is stamped even when the selected source has no value for that reference (`(null, null, source)`), or an unrated item would look mismatched forever and the no-op above could never trigger.
  - The five identical propagation bodies moved into `ReferenceRatingQueries` over the `IHasReferenceRating` entity interface - the fields are named identically on all five entities, so no per-domain field expressions are needed.
- **Endpoints (admin-only, on `ReferenceDataAdminController`):** `GET /api/reference-data/rating-sources`, `PUT /api/reference-data/rating-sources/{domain}` (validates source ∈ available, 400 otherwise), `POST
  /api/reference-data/rating-sources/{domain}/recompute`.
- **UI:** a "Primary rating source" card on the reference-data admin page - per selectable domain, a source button-group plus a **separate** Recompute button (two deliberate actions, not one) showing the checked/updated counts.
  It spells out the Metacritic caveat: `/100` and often absent on RAWG, so switching to it blanks the pill for many games and sorts them last.

### Phase 2 - IMDb ratings (movies/TV, via OMDb) - implemented

Movies/TV are now the second multi-source domain: alongside `tmdb` they carry an `imdb` entry on the same 0-10 scale, and their primary is admin-selectable through the exact step-1 mechanism (no new mechanism, no migration).

- **Source: OMDb, keyed by the IMDb id TMDB exposes.** IMDb has no public ratings API, so OMDb (`IOmdbClient`/`OmdbClient`) is the sanctioned path -
  the same shape as the book ISBN→Open Library fallback (primary provider hands off a cross-provider identifier, a secondary provider turns it into a rating stored under its own key).
  The IMDb id is native on `/movie/{id}` (`imdb_id`, zero extra calls); for TV the details call appends it via `?append_to_response=external_ids` (still one call, no season fan-out).
  Stored in `ExternalIds["imdb"]`.
- **OMDb is optional/best-effort.** `OmdbSettings.ApiKey` is nullable (not `required` like every other provider), and `AppConfiguration.OmdbSettings` coalesces a missing `Omdb` section to an empty instance;
  with no `Omdb__ApiKey` movies/TV just stay on their TMDB rating alone.
  `OmdbClient` no-ops with no key and treats OMDb's `"N/A"`/`Response:"False"` as "no rating" (never a stored 0).
  Config wiring adds `.AddProviderResilienceHandler()` like every other outbound client.
  The e2e/integration hosts need no OMDb key.
- **The daily quota is enforced, shared, and fail-safe** - OMDb's free tier is a hard 1000 calls/day, the only provider here with a limit low enough to hit in normal operation.
  - `OmdbCallBudget` is the single gate: no call site can bypass it, because the reservation lives inside `OmdbClient` rather than in each consumer.
    The count is a MongoDB document per (provider, UTC day) - `provider_quota`, `_id` = `"omdb:<yyyy-MM-dd>"`, TTL 7 days - reserved via the same atomic filtered upsert (`used < ceiling`, `$inc`, duplicate-key ⇒ refused) that
    `LeaseRepository` uses for mutual exclusion.
    A per-process counter would be wrong: the bulk consumers run under the reference-sync lease (one replica), but interactive resolves land on whichever replica served the request, so n replicas would each spend the full allowance.
    The day is part of the key, so the allowance renews with no reset job and no clock coordination beyond "everyone agrees what UTC day it is".
  - **Priority, not per-consumer caps.** `Omdb:DailyCallBudget` (1000) with `Omdb:InteractiveReserve` (50): `Interactive` (admin manual linking, Explore "add") may reach the whole allowance;
    `Background` stops short of the reserve, so a day of heavy backfilling can never make a user-facing action come back unrated.
    The reference sync and the Explore catalogue backfill run in that order on the same tick and draw from the same counter, which is what replaced Explore's hardcoded `ImdbBackfillBudget = 250` per domain (500/day whatever else was
    happening) with "spend whatever the sync left".
  - **Nothing throws.** `OmdbClient` returns `OmdbLookupResult` for every outcome including failure: it reads the body before the status (both of OMDb's 401s carry their explanation in JSON), and catches `HttpRequestException`,
    `TimeoutRejectedException`, `BrokenCircuitException`, `JsonException`/`NotSupportedException` and a pipeline timeout - enumerated, not a blanket catch, so a genuine bug still surfaces.
    The caller's own cancellation still propagates.
    This was a real bug: `GetFromJsonAsync` throws on the 401 an exhausted key answers with, and `AddImdbRatingAsync` is awaited unguarded inside `ResolveTvShowAsync`/`ResolveMovieAsync`, so an over-quota day turned admin linking and
    Explore "add" into 500s.
  - **Both 401s stop the day** via `MarkLimitReachedAsync` (shared write, so every replica sees it): `"Request limit reached!"` is the quota, and a rejected key can't be retried into working either.
    A local per-priority "exhausted on day N" flag then skips the database round trip per skipped call; keying it by day is what makes a stale value harmless.
  - **`OmdbLookupResult.Attempted` decides what may be recorded.** "OMDb answered and has nothing" is a fact (it's what lets the Explore backfill stop re-asking for 90 days); "we never got to ask" must leave no stamp at all.
    Conflating the two would write titles off over a limit that had nothing to do with them.
- **Catalog/resolver:** `RatingSourceCatalog` gains `[Movie] = [tmdb, imdb]` and `[TvShow] = [tmdb, imdb]` (default `tmdb`);
  the `"tmdb"`/`"imdb"` literals live there, and `.TvShowsAndMovies.cs`'s dict-key consts point at them. The movie/TV `PrimaryRating` call sites (resolve/refresh/link) now read `GetPrimaryRatingSourceAsync(Movie/TvShow)` instead of the old
  hardcoded `"tmdb"` const.
  `RecomputeReferenceRatingsAsync` gained one-line Movie/TvShow switch arms over the existing generic loop.
  Because the admin card/endpoints iterate `SelectableDomains`, movies/TV appeared in the "Primary rating source" UI with no controller/UI change.

**IMDb backfill bootstrap gotcha (found against the real dev database):** the `/changes` short-circuit (`LastEnrichedAt is not null && Ratings.Count > 0`) skips the full re-fetch once a `tmdb` rating exists, so a reference enriched before
Phase 2 has a tmdb rating (⇒ short-circuits) but no stored imdb id (only a full fetch writes that) - chicken-and-egg, so it never backfilled `imdb` (only the handful of references that happened to full-fetch got a rating -
the first symptom the user reported: "only 1 TV show and 1 movie have an IMDb rating").
Fixed by `BackfillImdbRatingAsync` on the no-change path: when the imdb rating is missing it resolves the imdb id cheaply via TMDB's dedicated `/{tv,movie}/{id}/external_ids` endpoint
(`ITmdbClient.GetTvShowImdbIdAsync`/`GetMovieImdbIdAsync` - one call, **no** season fan-out, deliberately not the full details re-fetch the short-circuit avoids), stores it, then does the one OMDb call.
Self-correcting: once the id is stored, later syncs skip the external-ids lookup; a title OMDb genuinely has no rating for just retries one cheap OMDb call per full sync, no persisted "attempted" marker - bounded now by the shared daily
budget, and skipped entirely (including the TMDB external-ids lookup, whose answer would be unusable) once that budget is spent.
Backfilling onto existing data is just a "Sync now" (or waiting for the periodic pass), never a `scripts/*.js`.

### Book cross-provider rating fallback

Google Books (the default book provider) **no longer serves ratings at all** (confirmed against the live API - `averageRating` is absent even for The Hobbit / Harry Potter).
So a small cross-provider fallback was added: when a book resolves via a provider that returns no rating but does have a clean, resolved ISBN, one Open Library call (`search.json?q=isbn:{isbn}`, first result) supplies a rating, stored under
the `openlibrary` source key.
It is skipped when a rating already exists, when the linking provider *is* Open Library, or when there is no ISBN.
It lives behind a dedicated one-method `IBookRatingByIsbnLookup` interface (implemented only by `OpenLibraryClient`) so the provider-agnostic `IBookReferenceClient` stays clean.

### UI

- List + grid rows: a compact bare `★ 7.8` pill in the shared per-type meta row (`*MetaRow.razor`), rendered nothing when there is no rating.
  Class `kt-ref-rating` in `app.css`.
- Detail pages: a per-source breakdown via the shared `ReferenceRatings.razor` component (`★ 8.2 / 10 TMDB (24,183)`), driven off the reference `Ratings` dict, so phase 2 sources appear automatically.
- Sort: a `Ref ★` option (kept short so it fits the narrow, mobile-sized sort control) added via `InventoryList`'s `HasReferenceRatingSort` flag and `ListSort.ReferenceRating`. Best-first, unrated last, a plain indexed sort on the tenant
  collection.

## Decisions locked (with the user)

- **Display:** bare number with a star (`★ 7.8`) in list/grid, no scale; fuller `value / scale source (count)` on the detail page.
- **Sort label:** `Ref ★` (short, mobile).
- **Primary-source selection:** shipped in Phase 1 as a **code default per media type**; now **admin-selectable and global** (not per-user), wired for video games (RAWG vs Metacritic) and movies/TV (TMDB vs IMDb) -
  see "Admin-selectable primary source" above.
  The code default is still the fallback when an admin hasn't chosen; per-user was ruled out because a switch must be a single bulk `SetReferenceRatingAsync` recompute per reference, which per-user couldn't be.
- **Video games:** RAWG's 0-5 user score is the primary (usually present); Metacritic is stored as a second source and shown on the detail page but does not drive the pill/sort (frequently absent).

## Known limitations

- **Google Books serves no ratings** - covered by the Open Library ISBN fallback above.
- **French (and other non-English) books often get no rating** - Open Library's rating coverage is thin outside English, and the ISBN must map to a work OL actually has ratings on.
  Confirmed by the user (English "Psion" got a rating, French titles did not).
  Accepted for now.
- **BnF books with no ISBN** get no rating (no lookup key) - expected edge.
- **Metacritic** is often absent on RAWG for smaller/older games.
- Non-TMDB providers have no cheap "has this changed" pre-check, so their `*Updated` sync counts always equal their `*Checked` counts (pre-existing behavior, unchanged).

## Tests added

- `ReferenceEnrichmentServiceTest` (unit, mocked): rating populate + primary-scalar propagation; no-rating-when-no-votes; TMDB backfill-forces-a-fetch; no-change short-circuit stays for an already-rated reference;
  TryLink sets the denormalized rating; the Open Library ISBN fallback fires for a non-OL provider and is skipped when the provider is OL.
- `MovieReferenceRatingRepositoryTest` (integration, real MongoDB): the `ReferenceRating` sort ordering (unrated last), `SetReferenceLinkAsync` stamps only unlinked matches, `SetReferenceRatingAsync` re-propagates to every already-linked
  item, and the `Ratings` dict round-trips through BSON.
- The other four types reuse the identical shared sort/propagation code the Movie tests cover; per-type integration tests were deliberately deferred (see next steps).
- `RatingSourceCatalogTest` (unit): video games offer RAWG+Metacritic (RAWG default), movies/TV offer TMDB+IMDb (TMDB default); the remaining single-source domains (Book/Album) are not yet selectable.
- `OmdbClientTest` (unit, stubbed handler): parses the rating + comma-separated vote count, returns null on `"N/A"`/unknown-id (`Response:"False"`), and makes no HTTP call when no key is configured.
- `ReferenceEnrichmentServiceTest` (unit, mocked) gained the IMDb slice: resolve adds the `imdb` rating and stores the imdb id in `ExternalIds` (even when OMDb has no rating yet, so the backfill has a key);
  imdb-as-selected-primary denormalizes imdb's value; the cheap no-change backfill adds imdb without a details re-fetch; the **bootstrap** case resolves a missing imdb id via the external-ids lookup then OMDb;
  no OMDb call when imdb is already present; movies recompute re-stamps with the selected source.
- `ReferenceEnrichmentServiceTest` (unit, mocked) gained: the source resolver (default / valid override / invalid-override-falls-back-to-default); `ResolveVideoGameAsync` denormalizes Metacritic's `/100` when it's the selected source;
  `RecomputeReferenceRatingsAsync` re-stamps every linked item with the selected source's value+scale, uses the default when unset, and throws for a non-selectable domain.

## What to do next

1. **~~Admin-selectable primary source (video games: RAWG vs Metacritic).~~ Done** - implemented as a general per-domain, admin/global setting in the shared `app_setting` collection plus a recompute action, wired for video games.
  See "Admin-selectable primary source (per-domain, admin/global) - implemented" above for the full shape.
  The same mechanism covers IMDb-vs-TMDB for movies/TV in Phase 2 for free (just add a `RatingSourceCatalog` entry and route those `PrimaryRating` call sites through `GetPrimaryRatingSourceAsync`).
2. **~~Phase 2 - IMDb ratings for movies/TV.~~ Done** - `imdb` source added via OMDb (keyed by the IMDb id TMDB exposes), optional/graceful when no OMDb key, primary admin-selectable through the step-1 mechanism, with a cheap external-ids
   backfill for the `/changes` short-circuit.
  See "Phase 2 - IMDb ratings (movies/TV, via OMDb) - implemented" above for the full shape and the backfill bootstrap gotcha.
3. **Phase 3 - "suggest N top-rated not-yet-added" feature.** Read a source, order the reference collection by `ratings.<source>.value` desc, skip titles the user already tracks, return the top N.
  This needs a supporting index on the chosen `ratings.<source>.value` path in `scripts/mongodb-create-index.js` (not added yet - phase 1 added no indexes because the per-owner tenant-side sort is small).
4. **Per-type integration + Playwright coverage.** Movies has real-Mongo integration coverage; add the equivalent for TV/game/album/book if desired (the logic is shared, so this is defense-in-depth, not filling a logic gap).
   The existing Book Playwright smoke test uses a synthetic seeded reference, so it does not exercise a real provider rating.
5. **French / non-English book ratings.** If it becomes worth it, try a second fallback source for books (e.g. a provider with better FR coverage) under the same `IBookRatingByIsbnLookup`-style pattern.
6. **Backfill existing data.** Ratings fill in on the next sync (`Sync now` on the reference-data admin page, or re-check a reference).
   No migration script is needed; if a bulk backfill is ever wanted it is just a forced sync, not a `scripts/*.js`.
7. **Docs.** Fold the durable parts of this into `CLAUDE.md`'s reference-data section once the feature settles (kept here as a working plan for now).
