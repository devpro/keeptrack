# Sync, Explore and import findings

Bugs found in the work that runs on a schedule or in the background: the periodic reference sync, the Explore catalogue and its exclusions, the rating recompute, and reference-data import.
Every finding below is fixed.

## Explore stopped recognising the video games the owner already tracks, because both halves of its exclusion failed on the same documents after the IGDB switch

Found on 2026-08-05, reported from the running app: Explore's movie and TV suggestions correctly hid what the owner tracks, while its video game suggestions did not.

Explore excludes a suggestion two ways, and the discovery provider change (RAWG → IGDB, `a8fdf40`) broke both at once for the same set of references:

- **By provider id.**
  `ExploreService` asks each linked reference document for `ExternalIds[discovery provider]`, which is now `igdb`.
  A reference linked while RAWG was the default carries only a `rawg` id until `TryAdoptDefaultVideoGameProviderAsync` gives it one, so it contributes nothing to the exclusion set.
  On the real dataset **105 of 344 video game references had not adopted** - among them Elden Ring, Red Dead Redemption 2, Disco Elysium, Mass Effect: Legendary Edition.
  Those are top-of-ranking titles, so the owner's own games led their Explore feed.
- **By title.**
  The fallback compared `TitleNormalizer.Normalize` (trim + lowercase) of the owner's item against the catalogue entry.
  After a link an item carries the *linking* provider's canonical title while the catalogue carries the *discovery* provider's, and the two catalogues spell one work differently in small systematic ways.
  Confirmed live against IGDB: `Mass Effect: Legendary Edition` vs `Mass Effect Legendary Edition`, `Disco Elysium: Final Cut` vs `Disco Elysium: The Final Cut`, and RAWG's habit of appending a remake's original year to the title (`GoldenEye 007 (1997)`).
  Exact equality rejected every one - **the same divergences that had blocked adoption**, so the fallback missed precisely the documents the id half had already missed.
  76 of those 105 were invisible to both.

Movies and TV were never affected: TMDB is both their discovery provider and the provider that linked every one of their references, so the id half always holds.

Three further consequences, all confirmed on real data:

- **Adoption's query was as wrong as its comparison.**
  It used IGDB's relevance `search`, which is documented here as noisy, with a 5-result window - a live probe for "Resident Evil" returned five bundles and archive re-releases, with neither the 1996 original nor the 2002 remake among them.
  And for a title carrying a `(1997)` disambiguator IGDB returns *nothing at all*, to either of its query shapes, so no comparison could have helped.
- **Duplicate reference documents.**
  Six works existed twice in the dev database (Elden Ring, RDR2, Baldur's Gate III, ...), once `rawg`-only and once `igdb`-only.
  `ReferenceDataImportService` matches by provider id then `_id` and never by title, so importing an IGDB-era export into a RAWG-era database creates exactly this.
  Tenants' items point at whichever document existed when they linked, splitting the work's ids, ratings and cover across two records.
- **`metacritic` was still admin-selectable** although no registered provider reports it.
  `MergeProviderRatings` preserves a RAWG-era value, so games linked back then kept showing a number while everything linked since resolved to no rating at all - a leak that hid itself.
  The root cause was that the per-domain source list was hardcoded, which is wrong in both directions: it would equally have kept offering IGDB's two scores on a deployment configured back to RAWG.

Fixed by restoring the invariant (every reference carries the current default provider's id) rather than working around it in Explore:

- `TitleNormalizer.NormalizeLoose`/`LooselyEqual` for provider-to-provider matching, and `StripDisambiguator` for re-querying without a `(year)` suffix.
  `Normalize` stays strict - it keys stored aliases, which are matched against tenant-typed text.
- `IVideoGameReferenceClient.FindGamesByExactTitleAsync` (IGDB `where name ~ "..."`, RAWG `search_exact` plus a client-side equality check), and a query ladder in `FindAdoptionCandidatesAsync` that widens only on an empty result.
- `VideoGameReferenceModel.ProviderAdoptionCheckedAt` so a fruitless attempt is remembered for 7 days instead of re-paid every pass.
- An admin **provider reconciliation** screen: the gap queue with per-row candidates and one-click adopt, and duplicate groups with a merge that re-points every tenant's item (`IVideoGameRepository.RepointReferenceAsync`) before deleting the absorbed document.
  The merge keeps a RAWG-linked document's cover whichever document survives (`MergedImageUrl`, the same rule as `PreferredImageUrl`), computed before the ids are unioned - afterwards the survivor carries a rawg id whatever its own cover is, and the test would pass for IGDB box art.
- `ReferenceDataImportSummary.PossibleDuplicates`, reported and logged rather than auto-merged - title text is not identity, and fusing two unrelated records is the one outcome nothing downstream could undo.
- `RatingSourceOptions` (injected) now derives the video game domain's selectable sources from its registered default provider, instead of a hardcoded list - so `ReferenceData:VideoGameProvider=rawg` brings `rawg`/`metacritic` back on its own.
  A stored override that isn't currently on offer is ignored but **never erased**, so an admin's Metacritic choice returns intact if RAWG does.
  `RatingSourceCatalog` keeps only the keys, scales and re-attempt window, so every key stays declared and stored values keep rendering whichever provider is active.
- Explore's title fallback now matches loosely too.

Measured against the live IGDB API over the real stuck set afterwards: **49 of 105 adopt unattended**, and the remainder reach the admin queue *with candidates* where they previously produced none.
What is left is genuinely ambiguous: IGDB holds three separate "FIFA 15" (2014) entries and two "Max Payne", which is exactly what the queue is for.

Explore dismissals recorded under `rawg` stay as they are, deliberately: the owner's call, so that switching back to a previous provider restores them.

## Reference-data import matched documents by the `_id` they were exported with, so importing into a non-empty database duplicated or failed outright

Found on 2026-08-04 while reviewing the feature before relying on it.

`POST /api/reference-data/import` looped each of the six collections straight into `UpsertAsync`, which replaces by `_id` with `IsUpsert = true`.
That is idempotent only against the database the export came from.
Anywhere else, an `_id` is a locally-minted value with no meaning: an environment that had already resolved "The Terminator" on its own held it under a different `_id`, so the import inserted a *second* document for the same TMDB id - which `movie_reference_tmdb_id` (unique, partial) rejects.
The write threw, `ApiExceptionFilterAttribute` turned it into a 500, and everything the loop had already written stayed (a zip is not a transaction).
The feature therefore only ever worked for its narrowest case: seeding an empty database.

Three further consequences, all only visible once matching was fixed:

- **Cast pointed at nothing.**
  `Cast[].PersonReferenceId`, `AuthorReferenceId` and `ArtistReferenceId` store a `person_reference` `_id`.
  Matching people by provider id without re-pointing the documents citing them leaves imported cast rows referencing ids the target doesn't have - and a missing person renders as no cast, so it fails silently.
- **A replace discarded what only the target knew**: `MatchedAliases` confirmed by its own tenants' searches, and `Ratings` from a provider the exporting environment never called (an `imdb` value costs a metered OMDb call).
- **`external_ids` uniqueness was declared for one provider per collection.**
  `book_reference` had an index for `openlibrary` (a fallback) but none for `googlebooks` (the default), and `person_reference` had one only for `tmdb` even though book authors and album artists are created under whichever provider linked their work.
  The application check was all that stood in the way of a duplicate there.

Fixed by `Domain/Services/ReferenceDataImportService.cs`: one generic algorithm over all six collections, matching by provider id (any key the document carries, so no provider is named in it), keeping the target's `_id`, importing people first and remapping every reference to them, merging instead of replacing, and leaving behind - and reporting - a provider id another document already claims rather than failing the run on it.
`scripts/mongodb-create-index.js` now declares the index per provider that can write each collection.

Guarded by `ReferenceDataImportResourceTest` (real HTTP, real MongoDB, one case per domain and per provider) - a mocked repository can't prove any of it, since the failure being prevented *is* the unique index firing.

## Reference-data import ran as a blocking request, so a real export always failed on the client's 100s HTTP timeout while the server kept importing

Confirmed in the running app on 2026-08-04 (local dev, a 2.5 MB export zip): the admin page reported `The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.`, with **nothing** in the WebApi logs - which reads like the request never arrived, but only because `appsettings.json` sets `"Microsoft": "Warning"` (so ASP.NET Core never logs request start/finish) and the import path itself logs only its skipped-external-id warnings, at the end.

The size of the file was misleading: a 2.5 MB zip is 11.7 MB of JSON and **17 468 documents** (14 757 people, 1 505 movies, 642 TV shows, 330 games, 160 books, 74 albums), and `ReferenceDataImportService` writes them one `InsertOne`/`ReplaceOne` at a time after reading all six collections whole.
That is minutes of work, run inside a single request/response - so `HttpClient`'s default 100s timeout cancelled the *client* while the server carried on importing to completion.
The user therefore saw a hard failure for work that had actually succeeded, and re-running it was the only way to find out.
This is exactly what CLAUDE.md's "long-running work runs as a background job, never a blocking request" rule exists to prevent; the endpoint predated the rule being applied to it, unlike TV Time import and `sync-now`.

Fixed by moving it onto the existing `JobStore<TStage, TResult>` machinery, the same shape as those two: `POST /api/reference-data/import` buffers the upload, starts the work on a fresh `IServiceScopeFactory.CreateScope()`, and returns **202** with a job id; `GET /api/reference-data/import/{jobId}` reports progress; the admin page polls it and shows a per-collection progress bar instead of a spinner that could only ever end in a timeout.
The job runs on `IHostApplicationLifetime.ApplicationStopping` and the import checks that token per document, so a shutdown mid-import stops promptly and says so, rather than writing against a disposed Mongo client - safe because the import is idempotent, so re-running the same zip picks up what didn't land.

Two smaller things on the same path, both real:

- `ReferenceDataAdminPage` handed `IBrowserFile.OpenReadStream()` straight to `StreamContent`, so the browser drip-feeding the file down the SignalR circuit happened *during* the POST and counted against its timeout.
  It's buffered into memory first now.
- Domain reports which collection it is writing (`ReferenceDataImportCollection`); naming that as a client-facing job stage stays in the web layer (`ReferenceDataImportStage`), since Domain can't reference `WebApi.Contracts`.

Still open, deliberately: the import is still one round trip per document, so a full export takes minutes even as a background job.
Batching the six collections into `BulkWrite` pages would cut that by an order of magnitude, but it touches all six repositories and the merge loop's incremental indexing (each saved document is indexed before the next is matched), and the timeout - the actual failure - is gone either way.

Files: `src/WebApi/ReferenceData/ReferenceDataAdminController.cs`, `src/Domain/Services/ReferenceDataImportService.cs`, `src/Domain/Models/ReferenceDataImportCollection.cs`, `src/Domain/Models/ReferenceRepositorySet.cs`, `src/WebApi.Contracts/Dto/ReferenceDataImportJobDto.cs`, `src/BlazorApp/Components/ReferenceDataAdmin/ReferenceDataAdminApiClient.cs`, `src/BlazorApp/Components/ReferenceDataAdmin/ReferenceDataAdminPage.razor`, `test/WebApi.IntegrationTests/Resources/ReferenceDataImportResourceTest.cs`

## The periodic sync read every reference document each tick, and the admin's rating recompute rewrote values that were already correct

`ReferenceSyncService` called `FindAllAsync()` and filtered `LastEnrichedAt` in memory, materializing whole collections - including every TV show's embedded episode guide - to then discard most of them, in MongoDB's natural order.
Replaced by `FindStaleAsync(cutoff, limit)`: a server-side filter and sort, stalest first, capped per pass.
The null half of that filter can't be folded into the date comparison (MongoDB compares within a type, so `$lte` against a date matches neither null nor missing), which would have made a never-enriched reference the one document the query could never return - the same silent-empty-match family as the `Eq(x => x.ReferenceId, null)` finding below.

`RecomputeReferenceRatingsAsync` had no way to know whether an item's denormalized rating was already on the selected source, so it read the whole reference collection and fired one `UpdateMany` per document on every click.
Tenant items now carry `ReferenceRatingSource` alongside the value, and the pass opens with a counted query that returns `(0, 0)` when nothing is mismatched.
The five copy-pasted per-domain sync loops and the five copy-pasted rating-propagation bodies were collapsed into one each while the code was open.
