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
