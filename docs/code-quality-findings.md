# Code quality findings

This document tracks a code review performed on 2026-07-06 against current .NET and MongoDB best practices.
Each finding is classified as a confirmed bug, a confirmed by-design behavior, or a known gap that is not yet implemented.
Update this file as items are fixed or as new reviews are performed.

## Fixed

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

1. `book_text`/`movie_text`/`tvshow_text`/`videogame_text` were dead. `Book`/`Movie`/`MusicAlbum`/`TvShow`/`VideoGame` all search via `builder.Where(f => f.Title.Contains(...))`, a regex filter that a MongoDB `text` index never accelerates. The only two repositories that call `builder.Text(...)` at all are `CarRepository` (via the base class default) and `CarHistoryRepository` - confirmed by grep, not assumption.
2. Following directly from (1): `car`/`car_history` had **no** index at all despite being the only two collections whose queries actually need one - this is the other half of "Car and CarHistory search relies on a `$text` index that does not exist" below, now fixed at the index level (the `CarHistoryRepository` code bug tracked separately below is not).
3. Beyond text search: almost every tenant-scoped collection (`book`, `car`, `car_history`, `movie`, `music-album`, `tvshow`, `videogame`) had no plain `{ owner_id: 1 }` index, even though every list/search request filters on `owner_id` first. The `movie_favorite`/`tvshow_favorite` partial indexes don't help a plain "all movies for this owner" query either - a partial index only accelerates queries the planner can prove only match documents inside its partial filter, and a plain list query has no `is_favorite` condition to prove that with.

Fixed by removing the four dead text indexes, adding `car_text`/`car_history_text`, and adding a plain `owner_id` index for every collection that lacked one (`episode` and the two favorite/want-to-watch pairs already had owner_id-prefixed indexes covering it).

File: `scripts/mongodb-create-index.js`

### Search was a no-op for Movie and Music Album

Fixed on 2026-07-06 while building the TV Time import feature (both repositories were touched anyway to add the `IsFavorite`/`WantToWatch` filters).
`MovieRepository.GetFilter` and `MusicAlbumRepository.GetFilter` built a MongoDB filter with `builder.Where(...)` but never combined the result back into the returned `filter`.
Both now do `filter &= builder.Where(...)`.
A regression test (`MovieResourceTest.MovieResourceSearch_FiltersToMatchingTitle_IsOk`) locks in the Movie fix; `MusicAlbum` still has no integration test at all (see "Thin test coverage" below), so its fix is unverified beyond the code change itself.

Files:

- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MusicAlbumRepository.cs`

## Confirmed bugs

These are true defects. They should be fixed.

### CarHistory treats a car ID as free text

`CarHistoryRepository.GetFilter` calls `builder.Text(input.CarId)`.
A car ID is an exact identifier, not a free-text search term, so this is the wrong filter type - the `car_history_text` index (see "Fixed" above) makes the collection searchable again, but doesn't fix this.
MongoDB also only allows one `$text` expression per query.
If both `input.CarId` and `search` are non-empty at the same time, the query throws ("only one $text expression allowed per query").

File: `src/Infrastructure.MongoDb/Repositories/CarHistoryRepository.cs`

Fix: filter `CarId` with an equality filter (`builder.Eq(f => f.CarId, input.CarId)`), not `Text`.

## Confirmed by design

These were reviewed with the project owner and are intentional. No action needed.

### Each entity searches its own fields

`Book` searches `Title` + `Series` + `Author`.
`VideoGame` adds exact-match filters on `Platform` and `State`.
`TvShow` and `Movie` (once fixed) search `Title` only.
This is intentional: each entity type exposes the search behavior that fits its own fields, not a shared generic contract.

## Known gaps (not yet implemented)

These are acknowledged as incomplete rather than deliberately permanent. Track and prioritize separately.

### `Car` has no controller or Blazor page

`ICarRepository`, `CarRepository`, and their DI registration exist, but there is no `CarController` and no Blazor Inventory page for `Car`.
Only `CarHistoryController` exists, and it references a `CarId` that currently cannot be created through the app.

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
`CarHistory`, `MusicAlbum`, and `VideoGame` still have none.
No test asserts ownership isolation (that user A cannot read, update, or delete user B's record).
There is no test project for `BlazorApp` - `AuthenticationController`'s Firebase-custom-claim-to-cookie-claim copy (added for the admin role) has no automated coverage as a result, only manual verification.
The reference-data admin endpoints have integration coverage for the non-admin-rejected (403) path and for the underlying Mongo queries directly (`TvShowReferenceLinkingTest`), but not for the admin-succeeds path over HTTP end-to-end, since that needs a second Firebase test user with the `role: admin` claim pre-set (see `CONTRIBUTING.md`).
`BookResourceTest` and `MovieResourceTest` are also close to copy-pasted; a generic/parameterized test base (mirroring `DataCrudControllerBase<TDto, TModel>` on the production side) would cover all resources without duplicating the test code per type.
