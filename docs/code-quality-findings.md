# Code quality findings

This document tracks a code review performed on 2026-07-06 against current .NET and MongoDB best practices.
Each finding is classified as a confirmed bug, a confirmed by-design behavior, or a known gap that is not yet implemented.
Update this file as items are fixed or as new reviews are performed.

## Fixed

### `mapper.Map<T>(null)` returned a fake empty object instead of null - also affected the shared base repository, not just the reference-data ones

Found again on 2026-07-09 while building the Car/CarHistory feature and its `CarResourceTest` integration coverage: `MongoDbRepositoryBase.FindOneAsync` (the base class every entity's repository extends) had the exact same shape as the bug described just below - `Mapper.Map<TModel>(await entities.FirstOrDefaultAsync())` - and hit the exact same `AllowNullDestinationValues = false` gotcha, silently returning a blank default model instead of `null` for a nonexistent id.
This meant `DataCrudControllerBase.GetById`'s `model == null` 404 check was broken for **every** entity type in the app (Book, Movie, TvShow, VideoGame, Album, Song, Playlist, Episode - not just the newly-added Car), returning 200 with an empty object instead of 404.
A mocked-repository unit test can't catch this (a mock never exercises real AutoMapper config); confirmed via a real MongoDB integration test (`CarResourceTest.CarResourceMetrics_ReturnsNotFound_ForACarThatDoesNotExist`) and cross-checked against `Book` directly.
Fixed the same way as the reference repositories below: check `entity is null` before calling `mapper.Map`, in the one shared base method rather than per-repository.

File: `src/Infrastructure.MongoDb/Repositories/MongoDbRepositoryBase.cs`

### `AllowNullDestinationValues = false` also substitutes an empty collection for a null reference-type member, not just an empty string

Found on 2026-07-09 while adding `CarHistoryResourceTest`: `CarHistoryModel -> CarHistory`'s `Coordinates` (`List<double>`) `ForMember` mapped to `null` when `Longitude`/`Latitude` were unset, but `AllowNullDestinationValues = false` substituted a new **empty list** instead - the same class of bug as the `Creator`/empty-string gotchas already documented here and in CLAUDE.md, just for a `List<T>` member instead of `string`.
The reverse mapping (`CarHistory -> CarHistoryModel`) read it back with `x.Coordinates != null ? x.Coordinates[0] : null`, which an empty-but-non-null list defeats - `x.Coordinates[0]` threw `IndexOutOfRangeException` on every `POST`/`PUT` of a `CarHistory` entry with no location set.
Fixed with `.AllowNull()` on that `ForMember`, same fix shape as the `Creator` case in CLAUDE.md.

File: `src/WebApi/MappingProfiles/CarDataStorageMappingProfile.cs`

### `mapper.Map<T>(null)` returned a fake empty object instead of null

Found on 2026-07-06 while adding the cast/actors integration test (`PersonReferenceRepositoryTest`), in `TvShowReferenceRepository`/`MovieReferenceRepository`/`PersonReferenceRepository`'s `Find*Async` methods.
Each did `var entity = await Collection.Find(...).FirstOrDefaultAsync(); return mapper.Map<TModel>(entity);` - when nothing matched, `entity` is `null`, and the same `AllowNullDestinationValues = false` AutoMapper setting behind the previous finding also changes `Map<TDestination>(null)`: instead of returning `null`, it returns a new, all-default `TDestination` instance.
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
It matched zero documents, because `AddAutoMapper` is configured with `AllowNullDestinationValues = false` (`WebApi/Program.cs`) - mapping a model whose string property is null stores an **empty string** in MongoDB, never an actual BSON null.
Every "is this string field unset" filter in the codebase needs to check for null *or* empty string, not just null.
Fixed by adding a shared `UnresolvedFilter()` helper (in both `TvShowRepository` and `MovieRepository`) that matches either.
This is a real-database-only bug: it doesn't throw, so a unit test against a mocked repository can't catch it - only `TvShowReferenceLinkingTest`, which runs the actual query against a real MongoDB instance, caught it (the assertion literally saw `"reference_id": ""` in the raw document via a diagnostic dump, not `null`).

Files:

- `src/Infrastructure.MongoDb/Repositories/TvShowRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`

### Index script had it backwards: dead text indexes on Book/Movie/TvShow/VideoGame, missing ones on Car/CarHistory, and no plain `owner_id` index almost anywhere

Found on 2026-07-06 during a review of `scripts/mongodb-create-index.js` requested directly against the actual repository query code (grepped every repository for `.Text(` usage rather than assuming the script matched).
Three separate problems, all in the same file:

1. `book_text`/`movie_text`/`tvshow_text`/`videogame_text` were dead. `Book`/`Movie`/`Album`/`TvShow`/`VideoGame` all search via `builder.Where(f => f.Title.Contains(...))`, a regex filter that a MongoDB `text` index never accelerates. The only two repositories that call `builder.Text(...)` at all are `CarRepository` (via the base class default) and `CarHistoryRepository` - confirmed by grep, not assumption.
2. Following directly from (1): `car`/`car_history` had **no** index at all despite being the only two collections whose queries actually need one - this is the other half of "Car and CarHistory search relies on a `$text` index that does not exist" below, now fixed at the index level (the `CarHistoryRepository` code bug tracked separately below is not).
3. Beyond text search: almost every tenant-scoped collection (`book`, `car`, `car_history`, `movie`, `album`, `tvshow`, `videogame`) had no plain `{ owner_id: 1 }` index, even though every list/search request filters on `owner_id` first. The `movie_favorite`/`tvshow_favorite` partial indexes don't help a plain "all movies for this owner" query either - a partial index only accelerates queries the planner can prove only match documents inside its partial filter, and a plain list query has no `is_favorite` condition to prove that with.

Fixed by removing the four dead text indexes, adding `car_text`/`car_history_text`, and adding a plain `owner_id` index for every collection that lacked one (`episode` and the two favorite/want-to-watch pairs already had owner_id-prefixed indexes covering it).

File: `scripts/mongodb-create-index.js`

### Search was a no-op for Movie and Album

Fixed on 2026-07-06 while building the TV Time import feature (both repositories were touched anyway to add the `IsFavorite`/`WantToWatch` filters).
`MovieRepository.GetFilter` and `MusicAlbumRepository.GetFilter` (renamed `AlbumRepository` on 2026-07-07, see "Reference data now covers five domains" below) built a MongoDB filter with `builder.Where(...)` but never combined the result back into the returned `filter`.
Both now do `filter &= builder.Where(...)`.
A regression test (`MovieResourceTest.MovieResourceSearch_FiltersToMatchingTitle_IsOk`) locks in the Movie fix; `AlbumResourceTest.AlbumResourceSearch_FiltersToMatchingTitleOrArtist_IsOk` (added 2026-07-07) now locks in the Album fix too, closing the gap this finding originally flagged.

Files:

- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/AlbumRepository.cs`

### CarHistory treated a car ID as free text, and CarRepository's search never covered the field that actually exists on a Car document

Fixed on 2026-07-09 while building the full Car/CarHistory feature (controller, Blazor pages, metrics, tests).
Two related bugs, both in search:

1. `CarHistoryRepository.GetFilter` called `builder.Text(input.CarId)` - a car ID is an exact identifier, not a free-text search term, and MongoDB only allows one `$text` expression per query, so supplying both `CarId` and a free-text `search` at the same time threw ("only one $text expression allowed per query").
2. `CarRepository` had no `GetFilter` override at all, so it fell back to `MongoDbRepositoryBase`'s default `builder.Text(search)`, which queried the `car_text` index (`{ title: "text" }`) - but `Car`'s BSON field is `commercial_name` (`[BsonElement("commercial_name")]` on `Name`), not `title`. The index never covered the field that exists on the document, so `Car` search had silently never worked at all, on top of (1) never being documented before this session.

Fixed by moving both repositories to the same `builder.Where(f => f.X.Contains(search, ...))` regex-search approach already used by Book/Movie/TvShow/VideoGame (`CarRepository` on `Name`, `CarHistoryRepository` on `Description`), filtering `CarId` with a plain `Eq`, and removing the now-unused `car_text`/`car_history_text` indexes from `scripts/mongodb-create-index.js` - closing out the last two exceptions that script's own comments used to call out.
Regression-tested against a real MongoDB instance: `CarHistoryResourceTest.CarHistoryResourceFilter_ByCarIdAndSearch_DoesNotThrow_IsOk` (the specific dual-filter case) and `CarResourceTest.CarResourceSearch_FiltersByName_IsOk`.

Files:

- `src/Infrastructure.MongoDb/Repositories/CarRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/CarHistoryRepository.cs`
- `scripts/mongodb-create-index.js`

## Confirmed by design

These were reviewed with the project owner and are intentional. No action needed.

### Each entity searches its own fields

`Book` searches `Title` + `Series` + `Author`.
`VideoGame` adds exact-match filters on `Platform` and `State`.
`TvShow` and `Movie` (once fixed) search `Title` only.
This is intentional: each entity type exposes the search behavior that fits its own fields, not a shared generic contract.

## Known gaps (not yet implemented)

These are acknowledged as incomplete rather than deliberately permanent. Track and prioritize separately.

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
`Album` and `VideoGame` gained full CRUD integration tests (`AlbumResourceTest`, `VideoGameResourceTest`) on 2026-07-07 while their controllers/repositories were touched anyway to add reference-data support - closing this finding for both. `Car` and `CarHistory` gained full CRUD integration tests (`CarResourceTest`, `CarHistoryResourceTest`) plus dedicated unit coverage for `CarMetricsService` on 2026-07-09, when the whole Car/CarHistory feature was built out (controller, Blazor pages, metrics) - closing this finding for both as well.
No test asserts ownership isolation (that user A cannot read, update, or delete user B's record).
There is no test project for `BlazorApp` - `AuthenticationController`'s Firebase-custom-claim-to-cookie-claim copy (added for the admin role) has no automated coverage as a result, only manual verification.
The reference-data admin endpoints have integration coverage for the non-admin-rejected (403) path and for the underlying Mongo queries directly (`TvShowReferenceLinkingTest`), but not for the admin-succeeds path over HTTP end-to-end, since that needs a second Firebase test user with the `role: admin` claim pre-set (see `CONTRIBUTING.md`).
`BookResourceTest` and `MovieResourceTest` are also close to copy-pasted; a generic/parameterized test base (mirroring `DataCrudControllerBase<TDto, TModel>` on the production side) would cover all resources without duplicating the test code per type.
