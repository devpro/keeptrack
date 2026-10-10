# Reference data

Provider metadata about a real work (cover, synopsis, cast, ratings), stored once and pointed at by every tenant's item through `ReferenceId`.
How an item is matched to a reference is in [Reference matching](reference-matching.md), and each provider's quirks are in [Providers](providers.md).

## Collections

`tvshow_reference`, `movie_reference`, `book_reference`, `videogame_reference`, `album_reference` and `person_reference` are the deliberate exception to "every collection has `owner_id`":
public facts about a real work, shared by every tenant.
Images are hotlinked from the provider CDN (TMDB's sanctioned pattern), so there is no local image storage.

- These repositories do not extend `IDataRepository<TModel>`/`MongoDbRepositoryBase`, both constrained to `IHasIdAndOwnerId` and owner-scoped CRUD.
  A new owner-less collection gets a small purpose-built repository.
- **People are deduplicated by provider person id, never by name** (`ResolvePersonReferenceIdAsync`, covering actors, authors and artists).
  References store only the person id, and `ReferenceDataController` hydrates names and pictures server side, which is why those DTO members are `[MapperIgnoreTarget]`.
- **External-id indexes are `unique: true` with `partialFilterExpression: { "external_ids.<key>": { $exists: true } }`**, not `sparse`, so documents missing the key do not collide on null.
  There is one index per provider that can write a collection, since a document holds ids from several, or a duplicate from a second provider passes unchecked:
  books cover `googlebooks`/`openlibrary`/`bnf`, and `person_reference` covers `tmdb`/`discogs`/`googlebooks`/`openlibrary`/`bnf` (`ResolvePersonReferenceIdAsync` is handed the linking client's `ProviderKey`).

## Enrichment

`ReferenceEnrichmentService` is the single place a title and identity resolve to a provider id.
It is one `partial class` split by domain file, each with `TryLinkExisting<X>ReferenceAsync`, `TryAutoResolve<X>Async`, `Resolve<X>Async` and `Refresh<X>ReferenceAsync`, and shared helpers in the core file.

Automatic resolution fires from `<X>Controller.OnCreatedAsync` and from `TvTimeImportService` on its own DI scope, never awaited inline.
`OnCreatedAsync` takes no `CancellationToken` on purpose, since the work it starts must outlive the request.

`Resolve<X>Async` looks up an existing reference **by provider id first** (`FindByExternalIdAsync`), then by the domain's identity, since title text cannot prevent duplicates and the provider id is invariant.

### What a link reaches

**A link reaches only the record it was made for** (`ReferenceLinkTarget`): creating an item, the check button and Explore's add link that one item, since another owner's copy is theirs to check.
Only an admin's link reaches other records: every unlinked one matching the title and year it was made with, plus the artist for an album, which the admin supplies.

`SetReferenceLinkAsync` also sets `Title`, `Year` and, per domain, `Author`/`Artist`/`Genre`/`Language` from the canonical record, but **never overwrites with nothing**.
`VideoGameModel.Platform`/`State` describe the tenant's own copy and are never overwritten.

A record update never changes a link (see [Architecture](architecture.md#request-flow)).

### Check for reference match

`TryLinkExisting<X>ReferenceAsync` backs `POST /api/<collection>/{id}/refresh-reference`, the control shown on every detail page to every authenticated user.

- It checks local references first and **escalates to the provider when nothing matches** (`Link<X>ReferenceAsync`), linking exactly what resolution on create would have.
- It does not short-circuit on an existing `ReferenceId`, since `Title`/`Year` are editable and replacing a bad match is the point.
- On a match it updates the tenant's document and no other record.
- On no match for a linked item, the link is cleared (`ReferenceId = ""`), returning it to the admin queue.
- Editing a field never searches by itself: the button is the only thing that re-resolves, so an item created without its identity field links once the field is added and the button pressed.

### Admin tools

`ReferenceDataAdminController` (`AdminOnly`, `/admin/reference-data`) covers the unresolved queue, manual search and link over a five-way `ReferenceItemType`, with provider-neutral `ExternalId`/`Provider` DTO fields.
Admin provider buttons select a provider, and exactly one control triggers the search.
Video game provider reconciliation is in [Reference matching](reference-matching.md#provider-reconciliation).

## Ratings

A rating has two homes.

1. **Canonical, on the reference** (`*ReferenceModel.Ratings`): a dictionary keyed by source, each `{ Value, Scale, Count }`.
   `Value` stays on the source's own scale (TMDB 10, Discogs and books 5, Metacritic 100) and is never normalized, since a list only ever sorts by one source.
2. **Denormalized, on the tenant item** (`ReferenceRating`, `ReferenceRatingScale`, `ReferenceRatingSource`): a copy of the primary source's value, so a list page displays and sorts by rating with no join.
   **It carries its source**, written by every path that writes the value, even when that source has no value, so a stored copy says which source it came from.

`RatingSourceCatalog` declares every source key a stored value can carry, its scale, and `RatingReattemptAfter` (90 days).
A source key is not a provider, so `rawg` and `metacritic` stay declared while stored values carry them.
`RatingSourceOptions` answers which sources a domain offers and which is effective.

- **The video game sources come from the default client's `SupportedRatingSources`**, never a hardcoded list, so switching provider needs no code or migration (a hardcoded list would offer `metacritic` under IGDB, which reports none).
- **A stored override that is not on offer is ignored, never erased**, which keeps a provider change reversible.
- Movies and TV are a fixed pair, TMDB and IMDb, since IMDb is a per-title lookup layered on TMDB (see [OMDb](providers.md#omdb)).
- Books have no selectable source: `BookPrimaryRating` reads whichever key the reference stores, which is why the source is nullable end to end.
  Google Books serves no ratings, so a book linked through a provider without one gets an Open Library rating by ISBN (`IBookRatingByIsbnLookup`), and books outside English often get none.

### Primary source

The primary source is an admin setting, global rather than per user, in `app_setting`, since a switch must be one bulk recompute per reference.
The admin card and the `rating-sources` GET, PUT and `recompute` endpoints are generic over `RatingSourceCatalog.SelectableDomains`, and the picker is a `form-select`.

A changed source applies to new links and syncs until the admin runs the recompute, which copies values references already hold onto tenant items and never calls a provider,
so "0 updated" is correct when the references themselves have no rating.

- **It opens with `CountLinkedOnOtherRatingSourceAsync`** and returns `(0, 0)` without reading references when nothing differs.
  An unstamped item counts as different, so the first run backfills.
- It is not a value-drift repair, which is the sync's job.
- **A batch is one projected read and one bulk write** (`RecomputeBatchSize` = 500): `FindRatingsAsync(afterId, limit)` pages by `_id`, and `SetReferenceRatingsAsync` writes one unordered `BulkWrite` of `UpdateMany`,
  shared in `ReferenceRatingQueries.cs` over `IHasReferenceRating`.

## Keeping references fresh

`ReferenceSyncBackgroundService` is an in-process `BackgroundService` on a 24h `PeriodicTimer` with an immediate pass at startup, rather than a Kubernetes CronJob.
Each tick tries `ILeaseRepository.TryAcquireAsync("reference-sync", Environment.MachineName, 1h)`, so one replica syncs per cycle (`LeaseRepositoryTest`).

`ReferenceSyncService.SyncStaleReferencesAsync` is the single algorithm behind the loop and `POST /api/reference-data/sync-now`.
The two differ only by the staleness windows, declared once in `ReferenceSyncWindows` (`Periodic`: 3 days for references, 7 for Explore; `Forced`: zero), guarded by `ReferenceSyncWindowsTest`.
`sync-now?force=true` rechecks everything, and without it runs exactly the background tick.
One failing document never aborts the run, and one generic loop covers five one-line domain arms (`SyncDomainAsync`).

**`I<X>ReferenceRepository.FindStaleAsync(cutoff, limit)` picks and orders the work** (`ReferenceStalenessQueries.cs`): never enriched first, then least recently enriched,
capped at `MaxDocumentsPerDomainPerPass` (500), so what a pass misses leads the next one.

**Gotcha: "never enriched" cannot come from the date comparison**, since `Lte(LastEnrichedAt, cutoff)` matches neither null nor missing.
`Eq(field, null)` matches both and BSON sorts null first, proven only by the real-MongoDB `ReferenceStalenessRepositoryTest`, and `last_enriched_at` is indexed on all five collections.

TV and movie refreshes pre-check TMDB's `/changes?start_date=...` and only bump `LastEnrichedAt` when nothing changed.
IGDB, RAWG, Discogs and the book providers have no equivalent, so they always fetch in full past the cutoff.

**Only the default video game provider is called on refresh**, unlike books, where a refresh checks every registered provider's key in `ExternalIds` (see [Providers](providers.md#multi-provider-domains)).

**Gotcha:** the service only runs when `Features:IsReferenceSyncEnabled` (default `true`, read every tick), which `KestrelWebAppFactory` sets `false`, so tests never fire real provider calls (see [Testing](testing.md)).

## Export and import

`GET/POST /api/reference-data/export` and `import` round-trip the six reference collections as a zip of JSON arrays.
`FindAllAsync()` exists only for the export, which serializes the models so Mapperly keeps it field-complete.

**The import is a background job** (202 plus a job id, `GET /api/reference-data/import/{jobId}`), and the upload is buffered on both sides.
A real export is about 17 000 documents written one at a time, which takes minutes and outlives `HttpClient`'s 100s timeout, and streaming the upload from the Blazor circuit would count against it.
The import is idempotent, so a re-run picks up what did not land.

**It matches by provider id, never by the exported `_id`** (`Domain/Services/ReferenceDataImportService.cs`, one algorithm over six collections through delegates).
An `_id` only means something in its source database: elsewhere the same TMDB id lives under another `_id`, and the unique external-id index rejects the insert.

- **The target's `_id` is kept**, since every tenant's `ReferenceId` points at it, and `_id` is the fallback only for a document with no provider id.
- **People are imported first**, and every citing document is re-pointed (`Cast[].PersonReferenceId`, `AuthorReferenceId`, `ArtistReferenceId`), since a missing person silently renders as no cast.
- **A match merges, never replaces**: `MatchedAliases` and `Ratings` are unioned (the target's metered OMDb values exist nowhere else), `RatingsCheckedAt` keeps the later attempt, and a missing value leaves the target's.
- A provider id another document claims is skipped and reported (`SkippedExternalIds`).
- An IGDB-linked export landing beside RAWG-linked copies of the same games is reported (`PossibleDuplicates`), never merged automatically, since title text is not identity.

`ReferenceDataImportResourceTest` covers each domain and provider over real HTTP and MongoDB, since the failure mode is the unique index firing.
Writing one document per round trip is a known limit (see [backlog](backlog.md)).
