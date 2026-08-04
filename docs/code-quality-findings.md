# Code quality findings

This document tracks a code review performed on 2026-07-06 against current .NET and MongoDB best practices.
Each finding is classified as a confirmed bug, a confirmed by-design behavior, or a known gap that is not yet implemented.
Update this file as items are fixed or as new reviews are performed.

## Sonar issues

1. S8970 — null-forgiving operator (60 of 67 issues, MINOR)

    Verdict: false positive, don't touch the code.

    This rule fires when Sonar's engine believes nullable warnings are disabled at that point, making ! a no-op.
    But BlazorApp.csproj has `<Nullable>enable</Nullable>` project-wide, and every flagged ! (e.g. `context.User.Identity!.Name!` in Manage.razor:8, `(bool)e.Value!` in several @onchange handlers) is a genuine, meaningful suppression
    against a real nullable-annotated API (ClaimsPrincipal.Identity, ChangeEventArgs.Value).

    This is a known SonarC# limitation with Razor-generated code: the source generator's nullable-context pragmas don't map cleanly back onto markup-embedded lambdas/expressions,
    so Sonar loses track of the enclosing #nullable enable region.

    Removing these ! would just reintroduce real CS8600/CS8602 build warnings.

    Recommendation: bulk-resolve rule S8970 as "False Positive" in the SonarCloud UI rather than editing 60 call sites.

## Fixed

### An id that names nothing reached the user as the generic error page instead of a 404, and an id that wasn't a valid ObjectId reached it as a 500

Found on 2026-08-04 while adding a real 404 page to the Blazor app.

Two independent defects on the same path, both ending at the error page for what is only ever a stale bookmark, a hand-edited URL or a deleted item.

- **A 404 from the API threw.** `InventoryApiClientBase.GetOneAsync` used `GetFromJsonAsync`, whose built-in `EnsureSuccessStatusCode` makes a 404 an `HttpRequestException`.
  Every one of the eleven detail pages already renders a `<type> not found.` state from a null item, and that branch was simply unreachable:
  the throw killed the circuit on an in-app navigation, and blew up the prerender pass into `/error` on a direct load.
  Now only a 404 returns null; every other failure still throws, since an outage must not render as an empty detail page.
- **A malformed id threw deeper down, as a 500.** Every entity behind `MongoDbRepositoryBase` maps `_id` as an ObjectId, so the driver runs the string in an id filter through `ObjectId.Parse` and raises `FormatException` on anything that
  isn't 24 hex digits - which `ApiExceptionFilterAttribute` turns into a 500.
  `GET/PUT/DELETE /api/movies/not-an-object-id` all returned 500 (confirmed against a real MongoDB, and reproduced as four failing tests before the fix).
  `MongoDbRepositoryBase` now answers "names no document" for such an id, exactly as it does for a well-formed id that was never minted.
  The guard also covers `DeleteAllByParentAsync`: the controller's `OnDeletedAsync` cascade hook runs on the raw route id whether or not the parent delete matched, so the id reaches the child collection's parent-id filter too.

`TvShowDetail` needed one further fix: alone among the detail pages it queried its child collection *before* checking the parent existed, so the episode query - filtered on the same id -
failed the whole page rather than letting it render "Show not found.".
Car/House/HealthProfile already had the parent-then-children order.

Still open, deliberately: a raw API caller can pass a malformed id as a *filter* (`GET /api/episodes?TvShowId=not-an-object-id`) and get a 500 from the child repository's `GetFilter`.
No UI path reaches it, and fixing it means touching each of the four child repositories rather than one shared method.

### Reference-data import matched documents by the `_id` they were exported with, so importing into a non-empty database duplicated or failed outright

Found on 2026-08-04 while reviewing the feature before relying on it.

`POST /api/reference-data/import` looped each of the six collections straight into `UpsertAsync`, which replaces by `_id` with `IsUpsert = true`.
That is idempotent only against the database the export came from.
Anywhere else, an `_id` is a locally-minted value with no meaning: an environment that had already resolved "The Terminator" on its own held it under a different `_id`, so the import inserted a *second* document for the same TMDB id - which
`movie_reference_tmdb_id` (unique, partial) rejects.
The write threw, `ApiExceptionFilterAttribute` turned it into a 500, and everything the loop had already written stayed (a zip is not a transaction).
The feature therefore only ever worked for its narrowest case: seeding an empty database.

Three further consequences, all only visible once matching was fixed:

- **Cast pointed at nothing.** `Cast[].PersonReferenceId`, `AuthorReferenceId` and `ArtistReferenceId` store a `person_reference` `_id`.
  Matching people by provider id without re-pointing the documents citing them leaves imported cast rows referencing ids the target doesn't have - and a missing person renders as no cast, so it fails silently.
- **A replace discarded what only the target knew**: `MatchedAliases` confirmed by its own tenants' searches, and `Ratings` from a provider the exporting environment never called (an `imdb` value costs a metered OMDb call).
- **`external_ids` uniqueness was declared for one provider per collection.** `book_reference` had an index for `openlibrary` (a fallback) but none for `googlebooks` (the default), and `person_reference` had one only for `tmdb` even though
  book authors and album artists are created under whichever provider linked their work.
  The application check was all that stood in the way of a duplicate there.

Fixed by `Domain/Services/ReferenceDataImportService.cs`: one generic algorithm over all six collections, matching by provider id (any key the document carries, so no provider is named in it), keeping the target's `_id`, importing people
first and remapping every reference to them, merging instead of replacing, and leaving behind - and reporting - a provider id another document already claims rather than failing the run on it.
`scripts/mongodb-create-index.js` now declares the index per provider that can write each collection.

Guarded by `ReferenceDataImportResourceTest` (real HTTP, real MongoDB, one case per domain and per provider) - a mocked repository can't prove any of it, since the failure being prevented *is* the unique index firing.

### Reference-data import ran as a blocking request, so a real export always failed on the client's 100s HTTP timeout while the server kept importing

Confirmed in the running app on 2026-08-04 (local dev, a 2.5 MB export zip): the admin page reported `The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing.`, with **nothing** in the WebApi logs - which
reads like the request never arrived, but only because `appsettings.json` sets `"Microsoft": "Warning"` (so ASP.NET Core never logs request start/finish) and the import path itself logs only its skipped-external-id warnings, at the end.

The size of the file was misleading: a 2.5 MB zip is 11.7 MB of JSON and **17 468 documents** (14 757 people, 1 505 movies, 642 TV shows, 330 games, 160 books, 74 albums), and `ReferenceDataImportService` writes them one
`InsertOne`/`ReplaceOne` at a time after reading all six collections whole.
That is minutes of work, run inside a single request/response - so `HttpClient`'s default 100s timeout cancelled the *client* while the server carried on importing to completion.
The user therefore saw a hard failure for work that had actually succeeded, and re-running it was the only way to find out.
This is exactly what CLAUDE.md's "long-running work runs as a background job, never a blocking request" rule exists to prevent; the endpoint predated the rule being applied to it, unlike TV Time import and `sync-now`.

Fixed by moving it onto the existing `JobStore<TStage, TResult>` machinery, the same shape as those two: `POST /api/reference-data/import` buffers the upload, starts the work on a fresh `IServiceScopeFactory.CreateScope()`, and returns
**202** with a job id; `GET /api/reference-data/import/{jobId}` reports progress; the admin page polls it and shows a per-collection progress bar instead of a spinner that could only ever end in a timeout.
The job runs on `IHostApplicationLifetime.ApplicationStopping` and the import checks that token per document, so a shutdown mid-import stops promptly and says so, rather than writing against a disposed Mongo client - safe because the
import is idempotent, so re-running the same zip picks up what didn't land.

Two smaller things on the same path, both real:

- `ReferenceDataAdminPage` handed `IBrowserFile.OpenReadStream()` straight to `StreamContent`, so the browser drip-feeding the file down the SignalR circuit happened *during* the POST and counted against its timeout.
  It's buffered into memory first now.
- Domain reports which collection it is writing (`ReferenceDataImportCollection`); naming that as a client-facing job stage stays in the web layer (`ReferenceDataImportStage`), since Domain can't reference `WebApi.Contracts`.

Still open, deliberately: the import is still one round trip per document, so a full export takes minutes even as a background job.
Batching the six collections into `BulkWrite` pages would cut that by an order of magnitude, but it touches all six repositories and the merge loop's incremental indexing (each saved document is indexed before the next is matched), and
the timeout - the actual failure - is gone either way.

Files: `src/WebApi/ReferenceData/ReferenceDataAdminController.cs`, `src/Domain/Services/ReferenceDataImportService.cs`, `src/Domain/Models/ReferenceDataImportCollection.cs`, `src/Domain/Models/ReferenceRepositorySet.cs`,
`src/WebApi.Contracts/Dto/ReferenceDataImportJobDto.cs`, `src/BlazorApp/Components/ReferenceDataAdmin/ReferenceDataAdminApiClient.cs`, `src/BlazorApp/Components/ReferenceDataAdmin/ReferenceDataAdminPage.razor`,
`test/WebApi.IntegrationTests/Resources/ReferenceDataImportResourceTest.cs`

### A slow Open Library discarded every book refresh, and pinned those books at the head of the staleness queue

Confirmed in the running app on 2026-08-04: a forced sync reported `booksChecked: 7, booksUpdated: 0` while every other domain refreshed normally, and the 7 book references kept a `last_enriched_at` from the previous day.

`AddOpenLibraryRatingFallbackAsync` (`ReferenceEnrichmentService.Books.cs`) documented itself as "best-effort - a failed/empty lookup just leaves the book unrated rather than failing the resolve", but awaited
`IBookRatingByIsbnLookup.GetRatingByIsbnAsync` unguarded.
Open Library's `search.json` went slow enough to blow `AddBookProviderResilienceHandler`'s 40s total timeout (measured directly: 36.4s, 40.9s, then a 503 on three consecutive calls), so `Polly.Timeout.TimeoutRejectedException` escaped
`RefreshBookReferenceAsync` **after** Google Books had already returned title, synopsis, cover, language and ISBN - discarding all of it, skipping the `UpsertAsync`, and never stamping `LastEnrichedAt`.

Two consequences.
The refresh was caught per-document by `ReferenceSyncService.SyncDomainAsync` and logged, so the pass merely looked idle;
and because nothing was stamped, the same books led the staleness queue on every subsequent pass, re-paying a 40s timeout each, unable to recover for as long as Open Library stayed slow.
The identical unguarded call also sat on the interactive path (`ResolveBookAsync`), where it meant a 40s wait and then a 500 from admin manual linking and from the auto-resolve a book creation fires.

Fixed by enforcing the documented contract at that boundary: the lookup is wrapped and logged, `OperationCanceledException` still propagates (a shutdown is not a provider being unhelpful, same exclusion as the sync's own per-document
catch), and the book keeps the linking provider's data.
Same rule, and the same reason, as `IOmdbClient` never throwing - an optional secondary provider must never be able to fail the primary operation.

That guard immediately surfaced the second half of the same bug, confirmed the same way: with the refresh no longer aborting, it wrote back a `Ratings` map rebuilt from the linking provider - which never carries this value -
so "The Hobbit"'s stored 4.29/498 and "Psion"'s 4.5/2 were **deleted** by a refresh that simply couldn't reach Open Library.
`AddOpenLibraryRatingFallbackAsync` now takes the previously stored rating and keeps it whenever the lookup never answered (a failure, or no ISBN to ask with), while an actual "no rating for this ISBN" response still clears it -
the same distinction `RebuildRatingsAsync` makes between "OMDb has nothing" and "we never asked".

Guarded by `RefreshBookReferenceAsync_KeepsTheLinkingProvidersData_WhenTheOpenLibraryRatingLookupFails`, `ResolveBookAsync_StillLinks_WhenTheOpenLibraryRatingLookupFails` (both verified to fail without the fix) and
`RefreshBookReferenceAsync_ClearsAKnownRating_WhenOpenLibraryAnswersWithNoRating`.

### An over-quota OMDb key turned admin manual linking and Explore "add" into 500s, and nothing bounded the calls that got it there

OMDb's free tier is 1000 calls/day and it answers an exhausted key with an HTTP **401**, which `GetFromJsonAsync` throws for.
`AddImdbRatingAsync` is awaited unguarded inside `ResolveTvShowAsync`/`ResolveMovieAsync`, so once the day's allowance was gone every manual link and every Explore "add" failed - despite `IOmdbClient` documenting that a missing IMDb rating
is never an error.
Any OMDb outage or timeout did the same thing.

Two consumers spent the key on the same 24h tick and neither could see the other: the Explore catalogue backfill was capped by a hardcoded 250 per domain (500/day whatever else was happening), while the reference sync's IMDb backfill had no
cap at all.
Nothing counted calls, and once the limit was hit a pass kept firing hundreds more doomed requests, each logged individually.

Fixed by `OmdbCallBudget` (a shared daily counter in `provider_quota`, reserved atomically so several replicas can't collectively overspend), a priority split that keeps a reserve for user-facing calls, and an `OmdbClient` that returns
`OmdbLookupResult` for every outcome instead of throwing - with both of OMDb's 401s writing the day off through the shared counter.
`OmdbLookupResult.Attempted` separates "OMDb has nothing for this title" from "we never asked", so a spent budget can no longer stamp a rating attempt and suppress a title for the whole re-attempt window.

### The periodic sync read every reference document each tick, and the admin's rating recompute rewrote values that were already correct

`ReferenceSyncService` called `FindAllAsync()` and filtered `LastEnrichedAt` in memory, materializing whole collections - including every TV show's embedded episode guide - to then discard most of them, in MongoDB's natural order.
Replaced by `FindStaleAsync(cutoff, limit)`: a server-side filter and sort, stalest first, capped per pass.
The null half of that filter can't be folded into the date comparison (MongoDB compares within a type, so `$lte` against a date matches neither null nor missing), which would have made a never-enriched reference the one document the query
could never return - the same silent-empty-match family as the `Eq(x => x.ReferenceId, null)` finding below.

`RecomputeReferenceRatingsAsync` had no way to know whether an item's denormalized rating was already on the selected source, so it read the whole reference collection and fired one `UpdateMany` per document on every click.
Tenant items now carry `ReferenceRatingSource` alongside the value, and the pass opens with a counted query that returns `(0, 0)` when nothing is mismatched.
The five copy-pasted per-domain sync loops and the five copy-pasted rating-propagation bodies were collapsed into one each while the code was open.

### The IMDb backfill re-bought the same "no rating" answer forever, and the recompute still cost a round trip per reference when it had work to do

Two leftovers from the OMDb-budget and recompute-no-op work above, both fixed on 2026-08-03.

`BackfillImdbRatingAsync` short-circuited only on an imdb rating being *present*, so a title IMDb genuinely has nothing for had nothing to short-circuit on:
every sync pass past the 3-day staleness cutoff paid a TMDB external-ids call and an OMDb call to learn the same thing again, indefinitely, and that traffic came out of the same 1000/day allowance the rated titles need.
The Explore catalogue backfill already solved this with a per-source attempt stamp; the reference documents now carry the same `RatingsCheckedAt` map on the same 90-day window (`RatingSourceCatalog.RatingReattemptAfter`, moved out of
`ExploreCatalogueRefreshService` so the two consumers share one declaration).
The window is checked before the id lookup, so both calls are skipped, and only an attempt OMDb actually answered is stamped.
Found alongside it: a full fetch rebuilt `Ratings` from TMDB and dropped a known imdb value whenever OMDb was unreachable - `RebuildRatingsAsync` now keeps it when the call never happened.

`RecomputeReferenceRatingsAsync` did nothing when nothing was mismatched, but when there *was* work it read every reference document whole (for TV, each show's entire embedded episode guide) and fired one `UpdateMany` round trip per
document.
It now pages a projected `_id` + `ratings` read by id cursor and writes each page back as a single unordered `BulkWrite`: two round trips per 500 references, none per tenant item.
The distinction matters as the user base grows - the items are re-stamped server-side inside each `UpdateMany`, so more users mean more documents written, never more round trips or more memory in the API.

### Project-wide Sonar review (main branch, not PR-scoped): S2365, ASP0025 ×2, CA1862 ×2, CA1859 ×3, JS S2486

Fixed on 2026-07-27, reviewed against `https://sonarcloud.io/project/issues?issueStatuses=OPEN&id=devpro_keeptrack` (28 open issues at the time, excluding 3 `S1135` "TODO" issues out of scope for this pass).

- **S2365** CRITICAL, `PlaylistDetail.razor:144` - `PlaylistSongs` was a property doing `.Select().Where().ToList()` on every access, read twice per render (`.Count` then `@foreach`).
  Renamed to a method, `GetPlaylistSongs()`, per convention (expensive/allocating work shouldn't look like a cheap property).
  No behavior change.
- **ASP0025** INFO × 2, `WebApi/Program.cs`, `BlazorApp/Program.cs` - both used the older `AddAuthorization(options => { options.AddPolicy(...); ... })` shape;
  switched to `AddAuthorizationBuilder().AddPolicy(...).AddPolicy(...)`, the modern .NET 8+ API.
  Same policies, same behavior.
- **CA1862** INFO × 2, `AlbumReferenceRepositoryTest.cs:103`, `BookReferenceRepositoryTest.cs:144` - test assertions did `m.Title == title.ToLowerInvariant()`; switched to `string.Equals(m.Title, title, StringComparison.OrdinalIgnoreCase)`.
- **CA1859** INFO × 3 - `AmazonOrderPreviewServiceTest.ToStream`/`GenericVideoGameImportServiceTest.ToStream` now return `MemoryStream` instead of `Stream`;
  `OpenLibraryClientTest.BuildClient` now returns `OpenLibraryClient` instead of `IBookReferenceClient` (checked call sites first -
  both members it exposes, `ProviderKey`/`GetBookDetailsAsync`, are public on the concrete class, not explicit interface implementations).
- **javascript S2486** MINOR, `ReconnectModal.razor.js:42` - `catch (err)` never used `err`, silently swallowing the exception.
  Added `console.error("Blazor reconnect failed:", err)`.

Investigated but confirmed **not** actionable during the same pass (left as-is, see "Sonar issues" note below for the rest of the 28):
`S8969` in `TvTimeImportService.cs:469-470` looked like the same Razor-generated-code false positive as `S8970` above, but is a **different, real** finding -
removing the `!` after `Dictionary<TKey,TModel>.TryGetValue`'s `out model!` reintroduces genuine `CS8601` warnings on rebuild (confirmed by actually removing it and rebuilding), because `[MaybeNullWhen(false)]` doesn't flow cleanly through
the open generic `TModel` parameter here.
Don't conflate the two rule ids - `S8970` (Razor markup, nullable context lost) is a false positive; `S8969` (plain `.cs`, "the compiler already knows") needs checking case-by-case, this one isn't.

Verification: full solution build (0 warnings/errors), full `WebApi.UnitTests` run (235/235 passed, includes the three CA1859-touched test classes).
Once a local MongoDB became available, also ran directly against it (`Local.runsettings` env vars loaded into the process, real Firebase auth):
`AlbumReferenceRepositoryTest`/`BookReferenceRepositoryTest` (the two `CA1862` files) - 7/7 passed;
`ReferenceDataAdminResourceTest` (real HTTP call through `[Authorize(Policy="AdminOnly")]`) plus `PlaylistResourceTest`/`BookResourceTest` (real HTTP calls through `[Authorize(Policy="MemberOnly")]`) -
9/9 passed (1 self-skipped, the opt-in `SyncNow_PollingReachesACompletedResult`) - this is what actually proves the `ASP0025` `AddAuthorizationBuilder` switch still enforces both policies correctly end-to-end, not just that the attribute is
present;
`BlazorApp.PlaywrightTests`' `PlaylistSmokeTest.AddAndDelete_PlaylistThroughTheList` (real browser, real Blazor Server circuit) - passed, proving `GetPlaylistSongs()` renders correctly post-rename.
That Playwright test still only exercises `GetPlaylistSongs()`'s empty-list branch (no song is ever added to the playlist in that test) - the populated-list/dangling-`SongId`-skip branch has no automated coverage before or after this
change; adding it would need a synthetic album+tracklist fixture (a bigger addition than the rename itself), flagged here rather than silently left uncovered.

Files: `src/BlazorApp/Components/Inventory/Pages/PlaylistDetail.razor`, `src/WebApi/Program.cs`, `src/BlazorApp/Program.cs`, `test/WebApi.IntegrationTests/Resources/AlbumReferenceRepositoryTest.cs`,
`test/WebApi.IntegrationTests/Resources/BookReferenceRepositoryTest.cs`, `test/WebApi.UnitTests/Services/AmazonOrderPreviewServiceTest.cs`, `test/WebApi.UnitTests/Services/GenericVideoGameImportServiceTest.cs`,
`test/WebApi.UnitTests/ReferenceData/OpenLibraryClientTest.cs`, `src/BlazorApp/Components/Layout/ReconnectModal.razor.js`

### S107 — too many parameters on `OwnedItemImportMergeService.ComputeCommitPlan`/`.MergeItem` and `AmazonImportController.CommitAsync`

Fixed on 2026-07-26 (PR #467 Sonar review).
All three methods carried the same six-delegate bundle
(`getExistingTitle`, `getExistingReferences`, `getItemTitle`, `getItemReference`, `createNew`, `appendOwnedCopy`) as separate parameters, pushing their signatures to 8/9/10 params.
This was the intentional "generic engine over delegates instead of an interface" design (still documented in CLAUDE.md), so the fix keeps that design - it just stops repeating the six delegates individually.
Bundled them into one new `OwnedItemImportAdapter<TModel, TRequestItem>` record (`Domain/Models/OwnedItemImportAdapter.cs`) and threaded that single value through instead,
cutting `ComputeCommitPlan` to 3 params, `MergeItem` to 6, and `CommitAsync` to 5 - no change in behavior or genericity, all 8 call sites (6 in `AmazonImportController`, 1 in `GenericVideoGameImportController`, 2 in
`OwnedItemImportMergeServiceTest`) construct the adapter inline the same way they used to pass the delegates.

Files: `src/Domain/Models/OwnedItemImportAdapter.cs`, `src/Domain/Services/OwnedItemImportMergeService.cs`, `src/WebApi/Controllers/AmazonImportController.cs`, `src/WebApi/Controllers/GenericVideoGameImportController.cs`,
`test/WebApi.UnitTests/Services/OwnedItemImportMergeServiceTest.cs`

### Title-only fallback ignored a tenant-recorded year, so two same-titled but genuinely different items could be silently linked to the same reference document - or, worse, merged into one via `Resolve*Async`

Found on 2026-07-19 (real user report: linking "Road House" (2024) then checking the 1990 original for a match linked it to the 2024 reference instead).
Both `TryLinkExisting{TvShow,Movie,Book,VideoGame,Album}ReferenceAsync` **and** `Resolve{TvShow,Movie,Book,VideoGame,Album}Async` looked up `FindByTitleYearAsync(title, year)` and,
on a miss, unconditionally fell back to `FindByTitleAsync(title)` - a title-only lookup that ignores year entirely.
That fallback exists for a real need (a tenant with *no* year recorded at all can never match via the title+year query, since `MatchedAliases` requires both fields on the same element -
see the "title-only fallback... must run unconditionally... when Year is null" note further up this codebase's history), but the fix that made it unconditional went too far:
it also fired when the tenant/admin *had* a specific year that simply wasn't yet a confirmed alias, silently ignoring that year and matching whichever same-titled reference document `FindByTitleAsync` happened to return first.
The `TryLinkExisting*` half of the bug was fixed first and initially believed to be the whole story, but the user reproduced the exact same symptom afterward -
the real, more serious instance was in `Resolve*Async` (the method the admin's manual "link" action and the automatic single-candidate resolver actually call to create/upsert the reference document).
There, the wrongly-matched document's `Id` is reused for the upsert (`Id = existing?.Id`), so a year-blind title-only match didn't just link the wrong reference -
it **overwrote** the unrelated document (e.g. the 2024 remake's reference data got replaced by the 1990 original's), a de-facto merge of two distinct real items into one.
Fixed in both call sites by only taking the title-only fallback when the caller's `year` is `null` - when a specific year is known but doesn't match, the item is left unresolved (or unlinked) rather than guessed at,
consistent with this codebase's "don't guess when you don't have the info" principle elsewhere (Watch Next, `TryAutoResolve*Async`).
Covered by `ReferenceEnrichmentServiceTest.TryLinkExisting{TvShow,Movie}ReferenceAsync_DoesNotFallBackToTitleOnlyMatch_WhenTenantHasAYearButTitleYearMatchMisses`
and `ResolveMovieAsync_DoesNotMergeIntoAnUnrelatedSameTitledReference_WhenResolvingADifferentTmdbIdWithItsOwnKnownYear`.

Files: `src/WebApi/ReferenceData/ReferenceEnrichmentService.TvShowsAndMovies.cs`, `.Books.cs`, `.Albums.cs`, `.VideoGames.cs`

### BnF's own `"and (bib.author ...)"` CQL combination is not a strict intersection - candidates not actually matching the requested author silently leaked into search results

Found on 2026-07-19 (real user report: "when I search BnF it doesn't consider the author") while BnF was the second registered book provider.
Confirmed directly against the real API: a query for title "La Peste" and author "Victor Hugo" (who never wrote a book by that title) returned several genuine Victor Hugo anthologies instead of zero results,
none of them actually titled "La Peste".
The same query shape correctly narrows to 69 genuine matches when the *correct* author (Albert Camus) is used, so the server-side clause isn't useless, just not trustworthy as a hard filter on its own -
it appears to fall back to relevance-ranked results for the author alone when no record actually satisfies both criteria, rather than returning an empty set.
Fixed by adding a client-side post-filter (`BnfClient.AuthorMatches`,
a normalized word-presence check reusing `TitleNormalizer.Normalize`) that discards any parsed candidate whose own author text doesn't actually contain every word of the requested author, instead of trusting BnF's own filtering.
Covered by `BnfClientTest.SearchBooksAsync_FiltersOutCandidatesWhoseAuthorDoesNotActuallyMatch`.

File: `src/WebApi/ReferenceData/BnfClient.cs`

### `RefreshBookReferenceAsync` only ever checked the currently-configured default provider's key, not whichever provider a reference was actually linked through

Found on 2026-07-19 while adding a second book reference provider (BnF, alongside Open Library) and letting an admin pick either one per search/link action instead of only a deployment-wide config switch.
`RefreshBookReferenceAsync` read `reference.ExternalIds.GetValueOrDefault(bookReferenceClient.ProviderKey)`, where `bookReferenceClient` was the single injected client for whichever provider `ReferenceData:BookProvider` currently names.
Once a book reference could be linked through a *different* registered provider than the current default (e.g. linked via BnF while the deployment default stays Open Library),
the periodic/on-demand sync would find no id under the default's key and silently no-op that reference forever - it would never refresh again, with no error surfaced anywhere.
Fixed by resolving against every currently-registered provider's key (`BookReferenceClientRegistry.All.FirstOrDefault(c => reference.ExternalIds.ContainsKey(c.ProviderKey))`) instead of a single injected client's key.
Covered by `ReferenceEnrichmentServiceTest.RefreshBookReferenceAsync_RefreshesViaANonDefaultRegisteredProvider_WhenThatsTheOnlyOnePresent`.

File: `src/WebApi/ReferenceData/ReferenceEnrichmentService.Books.cs`

Several findings below trace back to AutoMapper's profile-wide `AllowNullDestinationValues = false` (a null source string/collection/object silently substituted with `""`/an empty collection/a blank instance).
AutoMapper itself was removed in favor of Riok.Mapperly (see `docs/automapper-removal-plan.md`), which preserves nulls by default.
The entire class of gotcha these findings patched around is now structurally impossible, not just individually fixed.
The `entity is null` guards these findings added stay in place regardless: Mapperly throws on a null source, so checking before mapping is still the only correct way to turn "no document matched" into a `null` return value.

### `mapper.Map<T>(null)` returned a fake empty object instead of null - also affected the shared base repository, not just the reference-data ones

Found again on 2026-07-09 while building the Car/CarHistory feature and its `CarResourceTest` integration coverage.
`MongoDbRepositoryBase.FindOneAsync` (the base class every entity's repository extends) had the exact same shape as the bug described just below - `Mapper.Map<TModel>(await entities.FirstOrDefaultAsync())`.
It hit the exact same `AllowNullDestinationValues = false` gotcha, silently returning a blank default model instead of `null` for a nonexistent id.
This meant `DataCrudControllerBase.GetById`'s `model == null` 404 check was broken for **every** entity type in the app (Book, Movie, TvShow, VideoGame, Album, Song, Playlist, Episode - not just the newly-added Car).
It returned 200 with an empty object instead of 404.
A mocked-repository unit test can't catch this (a mock never exercises real AutoMapper config).
Confirmed via a real MongoDB integration test (`CarResourceTest.CarResourceMetrics_ReturnsNotFound_ForACarThatDoesNotExist`) and cross-checked against `Book` directly.
Fixed the same way as the reference repositories below: check `entity is null` before calling `mapper.Map`, in the one shared base method rather than per-repository.

File: `src/Infrastructure.MongoDb/Repositories/MongoDbRepositoryBase.cs`

### `AllowNullDestinationValues = false` also substitutes an empty collection for a null reference-type member, not just an empty string

Found on 2026-07-09 while adding `CarHistoryResourceTest`: `CarHistoryModel -> CarHistory`'s `Coordinates` (`List<double>`) `ForMember` mapped to `null` when `Longitude`/`Latitude` were unset.
But `AllowNullDestinationValues = false` substituted a new **empty list** instead.
This was the same class of bug as the `Creator`/empty-string gotchas already documented here and in CLAUDE.md, just for a `List<T>` member instead of `string`.
The reverse mapping (`CarHistory -> CarHistoryModel`) read it back with `x.Coordinates != null ? x.Coordinates[0] : null`, which an empty-but-non-null list defeats.
`x.Coordinates[0]` threw `IndexOutOfRangeException` on every `POST`/`PUT` of a `CarHistory` entry with no location set.
Fixed with `.AllowNull()` on that `ForMember`, same fix shape as the `Creator` case in CLAUDE.md.
The `AllowNull()` opt-out itself no longer exists - the AutoMapper -> Mapperly migration deleted `CarDataStorageMappingProfile` entirely;
the same null-vs-empty-list handling now lives, hand-written, in `CarHistoryStorageMapper.BuildLocation`.

File (at the time of the fix): `src/WebApi/MappingProfiles/CarDataStorageMappingProfile.cs`, now `src/Infrastructure.MongoDb/Mappers/CarHistoryStorageMapper.cs`

### `mapper.Map<T>(null)` returned a fake empty object instead of null

Found on 2026-07-06 while adding the cast/actors integration test (`PersonReferenceRepositoryTest`), in `TvShowReferenceRepository`/`MovieReferenceRepository`/`PersonReferenceRepository`'s `Find*Async` methods.
Each did `var entity = await Collection.Find(...).FirstOrDefaultAsync(); return mapper.Map<TModel>(entity);`.
When nothing matched, `entity` is `null`, and the same `AllowNullDestinationValues = false` AutoMapper setting behind the previous finding also changes `Map<TDestination>(null)`.
Instead of returning `null`, it returns a new, all-default `TDestination` instance.
The integration test's `found.Should().BeNull()` assertion caught it directly (`found` was a non-null `PersonReferenceModel` with every property null).
This silently broke "not found" handling anywhere these methods were used with an `is null` check, including `ReferenceDataController`'s 404 responses.
Fixed by checking `entity is null` before calling `mapper.Map` in all three repositories, returning `null` directly instead.

Files:

- `src/Infrastructure.MongoDb/Repositories/TvShowReferenceRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MovieReferenceRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/PersonReferenceRepository.cs`

### `Eq(x => x.ReferenceId, null)` never matched a document, because it was never actually null

Found on 2026-07-06 while building the reference-data (TMDB) feature, in the first draft of `TvShowRepository.SetReferenceIdForTitleYearAsync`/`FindDistinctUnresolvedTitleYearsAsync`.
The filter checked `Builders<TvShow>.Filter.Eq(f => f.ReferenceId, null)`, expecting it to match every show that had never been linked.
It matched zero documents, because `AddAutoMapper` is configured with `AllowNullDestinationValues = false` (`WebApi/Program.cs`) -
mapping a model whose string property is null stores an **empty string** in MongoDB, never an actual BSON null.
Every "is this string field unset" filter in the codebase needs to check for null *or* empty string, not just null.
Fixed by adding a shared `UnresolvedFilter()` helper (in both `TvShowRepository` and `MovieRepository`) that matches either.
This is a real-database-only bug: it doesn't throw, so a unit test against a mocked repository can't catch it.
Only `TvShowReferenceLinkingTest`, which runs the actual query against a real MongoDB instance, caught it (the assertion literally saw `"reference_id": ""` in the raw document via a diagnostic dump, not `null`).

Files:

- `src/Infrastructure.MongoDb/Repositories/TvShowRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`

### Index script had it backwards: dead text indexes on Book/Movie/TvShow/VideoGame, missing ones on Car/CarHistory, and no plain `owner_id` index almost anywhere

Found on 2026-07-06 during a review of `scripts/mongodb-create-index.js` requested directly against the actual repository query code (grepped every repository for `.Text(` usage rather than assuming the script matched).
Three separate problems, all in the same file:

1. `book_text`/`movie_text`/`tvshow_text`/`videogame_text` were dead.
   `Book`/`Movie`/`Album`/`TvShow`/`VideoGame` all search via `builder.Where(f => f.Title.Contains(...))`, a regex filter that a MongoDB `text` index never accelerates.
   The only two repositories that call `builder.Text(...)` at all are `CarRepository` (via the base class default) and `CarHistoryRepository` - confirmed by grep, not assumption.
2. Following directly from (1): `car`/`car_history` had **no** index at all despite being the only two collections whose queries actually need one.
   This is the other half of "Car and CarHistory search relies on a `$text` index that does not exist" below, now fixed at the index level (the `CarHistoryRepository` code bug tracked separately below is not).
3. Beyond text search: almost every tenant-scoped collection (`book`, `car`, `car_history`, `movie`, `album`, `tvshow`, `videogame`) had no plain `{ owner_id: 1 }` index, even though every list/search request filters on `owner_id` first.
   The `movie_favorite`/`tvshow_favorite` partial indexes don't help a plain "all movies for this owner" query either.
   A partial index only accelerates queries the planner can prove only match documents inside its partial filter, and a plain list query has no `is_favorite` condition to prove that with.

Fixed by removing the four dead text indexes, adding `car_text`/`car_history_text`, and adding a plain `owner_id` index for every collection that lacked one.
`episode` and the two favorite/want-to-watch pairs already had owner_id-prefixed indexes covering it, so those were left alone.

File: `scripts/mongodb-create-index.js`

### Search was a no-op for Movie and Album

Fixed on 2026-07-06 while building the TV Time import feature (both repositories were touched anyway to add the `IsFavorite`/`WantToWatch` filters).
`MovieRepository.GetFilter` and `MusicAlbumRepository.GetFilter` (renamed `AlbumRepository` on 2026-07-07, see "Reference data now covers five domains" below) built a MongoDB filter with `builder.Where(...)`.
But it never combined the result back into the returned `filter`.
Both now do `filter &= builder.Where(...)`.
A regression test (`MovieResourceTest.MovieResourceSearch_FiltersToMatchingTitle_IsOk`) locks in the Movie fix.
`AlbumResourceTest.AlbumResourceSearch_FiltersToMatchingTitleOrArtist_IsOk` (added 2026-07-07) now locks in the Album fix too, closing the gap this finding originally flagged.

Files:

- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/AlbumRepository.cs`

### CarHistory treated a car ID as free text, and CarRepository's search never covered the field that actually exists on a Car document

Fixed on 2026-07-09 while building the full Car/CarHistory feature (controller, Blazor pages, metrics, tests).
Two related bugs, both in search:

1. `CarHistoryRepository.GetFilter` called `builder.Text(input.CarId)`.
   A car ID is an exact identifier, not a free-text search term, and MongoDB only allows one `$text` expression per query.
   So supplying both `CarId` and a free-text `search` at the same time threw ("only one $text expression allowed per query").
2. `CarRepository` had no `GetFilter` override at all, so it fell back to `MongoDbRepositoryBase`'s default `builder.Text(search)`, which queried the `car_text` index (`{ title: "text" }`).
   But `Car`'s BSON field is `commercial_name` (`[BsonElement("commercial_name")]` on `Name`), not `title`.
   The index never covered the field that exists on the document, so `Car` search had silently never worked at all, on top of (1) never being documented before this session.

Fixed by moving both repositories to the same `builder.Where(f => f.X.Contains(search, ...))` regex-search approach already used by Book/Movie/TvShow/VideoGame (`CarRepository` on `Name`, `CarHistoryRepository` on `Description`).
This also included filtering `CarId` with a plain `Eq`, and removing the now-unused `car_text`/`car_history_text` indexes from `scripts/mongodb-create-index.js`.
This closed out the last two exceptions that script's own comments used to call out.
Regression-tested against a real MongoDB instance: `CarHistoryResourceTest.CarHistoryResourceFilter_ByCarIdAndSearch_DoesNotThrow_IsOk` (the specific dual-filter case) and `CarResourceTest.CarResourceSearch_FiltersByName_IsOk`.

Files:

- `src/Infrastructure.MongoDb/Repositories/CarRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/CarHistoryRepository.cs`
- `scripts/mongodb-create-index.js`

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

### Playwright: an inventory list row intermittently isn't visible under a full parallel run (triaged 2026-07-31 - do not re-investigate from scratch)

**Symptom:** in a full `dotnet test` of `BlazorApp.PlaywrightTests`, exactly one test usually fails with
`Locator expected to be visible / element(s) not found` waiting for `.kt-item-row` filtered to the title it just created.
It is not always the same test - `ListStateSmokeTest.Search_PersistsInUrl_AndSurvivesBackNavigationFromDetail` and
`BookSmokeTest.AddEditAndDelete_BookThroughTheList` have both been observed - which is the signature of a flake rather than a defect in any one test.

**Already established, so nobody spends time re-deriving it:**

- Each affected test passes reliably when run in isolation (its own class, repeated runs).
- It is **not** caused by the test-cleanup rework of 2026-07-31: a full run on the pre-change code fails the same way, one test, same assertion.
- Every affected assertion is a books-list row lookup, and books are the busiest collection in a parallel run
  (Book/ListState/Ownership/Reference/GoogleBooks and both import smoke tests all create books against the same tenant).
- The Playwright expect timeout for these assertions is the 5s default.

**Not yet done:** finding the actual cause.
The plausible candidates are list-read latency under concurrent load against the shared tenant
(in which case the fix is a longer timeout on these specific assertions, not a global one) or a genuine enhanced-navigation render race.
Decide between them before changing anything - raising timeouts blindly would hide the second case.

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
