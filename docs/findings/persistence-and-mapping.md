# Persistence and mapping findings

Bugs found in MongoDB filters, indexes and object mapping, including the AutoMapper null behaviour that caused several of them before Riok.Mapperly replaced it.
Every finding below is fixed.
These are the findings a mocked-repository unit test could never have caught.

## `mapper.Map<T>(null)` returned a fake empty object instead of null

Found on 2026-07-06 in the reference repositories, and again on 2026-07-09 in `MongoDbRepositoryBase.FindOneAsync`.
Each `Find*Async` did `mapper.Map<TModel>(await ...FirstOrDefaultAsync())`, and AutoMapper's `AllowNullDestinationValues = false` turned a null source into a new all-default model.
Every "not found" check downstream was defeated: `DataCrudControllerBase.GetById` answered 200 with an empty object instead of 404 for every entity type, and `ReferenceDataController` never answered 404.
Caught only by real-MongoDB tests (`PersonReferenceRepositoryTest`, `CarResourceTest.CarResourceMetrics_ReturnsNotFound_ForACarThatDoesNotExist`), never by a mocked repository.
Fixed by checking `entity is null` before mapping, once in the base class and in each reference repository.
The rule outlived AutoMapper, since Mapperly throws on a null source instead.

Files: `src/Infrastructure.MongoDb/Repositories/MongoDbRepositoryBase.cs`, `TvShowReferenceRepository.cs`, `MovieReferenceRepository.cs`, `PersonReferenceRepository.cs`

## `AllowNullDestinationValues = false` also substitutes an empty collection for a null reference-type member, not just an empty string

Found on 2026-07-09 while adding `CarHistoryResourceTest`: `CarHistoryModel -> CarHistory`'s `Coordinates` (`List<double>`) `ForMember` mapped to `null` when `Longitude`/`Latitude` were unset.
But `AllowNullDestinationValues = false` substituted a new **empty list** instead.
This was the same class of bug as the `Creator`/empty-string gotchas already documented here, just for a `List<T>` member instead of `string`.
The reverse mapping (`CarHistory -> CarHistoryModel`) read it back with `x.Coordinates != null ? x.Coordinates[0] : null`, which an empty-but-non-null list defeats.
`x.Coordinates[0]` threw `IndexOutOfRangeException` on every `POST`/`PUT` of a `CarHistory` entry with no location set.
Fixed with `.AllowNull()` on that `ForMember`, the same fix shape as the `Creator` case.
The `AllowNull()` opt-out itself no longer exists - the AutoMapper -> Mapperly migration deleted `CarDataStorageMappingProfile` entirely;
the same null-vs-empty-list handling now lives, hand-written, in `CarHistoryStorageMapper.BuildLocation`.

File (at the time of the fix): `src/WebApi/MappingProfiles/CarDataStorageMappingProfile.cs`, now `src/Infrastructure.MongoDb/Mappers/CarHistoryStorageMapper.cs`

## `Eq(x => x.ReferenceId, null)` never matched a document, because it was never actually null

Found on 2026-07-06 while building the reference-data (TMDB) feature, in the first draft of `TvShowRepository.SetReferenceIdForTitleYearAsync`/`FindDistinctUnresolvedTitleYearsAsync`.
The filter checked `Builders<TvShow>.Filter.Eq(f => f.ReferenceId, null)`, expecting it to match every show that had never been linked.
It matched zero documents, because `AddAutoMapper` is configured with `AllowNullDestinationValues = false` (`WebApi/Program.cs`) - mapping a model whose string property is null stores an **empty string** in MongoDB, never an actual BSON null.
Every "is this string field unset" filter in the codebase needs to check for null *or* empty string, not just null.
Fixed by adding a shared `UnresolvedFilter()` helper (in both `TvShowRepository` and `MovieRepository`) that matches either.
This is a real-database-only bug: it doesn't throw, so a unit test against a mocked repository can't catch it.
Only `TvShowReferenceLinkingTest`, which runs the actual query against a real MongoDB instance, caught it (the assertion literally saw `"reference_id": ""` in the raw document via a diagnostic dump, not `null`).

Files:

- `src/Infrastructure.MongoDb/Repositories/TvShowRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`

## Index script had it backwards: dead text indexes on Book/Movie/TvShow/VideoGame, missing ones on Car/CarHistory, and no plain `owner_id` index almost anywhere

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

## Search was a no-op for Movie and Album

Fixed on 2026-07-06 while building the TV Time import feature (both repositories were touched anyway to add the `IsFavorite`/`WantToWatch` filters).
`MovieRepository.GetFilter` and `MusicAlbumRepository.GetFilter` (renamed `AlbumRepository` on 2026-07-07) built a MongoDB filter with `builder.Where(...)`.
But it never combined the result back into the returned `filter`.
Both now do `filter &= builder.Where(...)`.
A regression test (`MovieResourceTest.MovieResourceSearch_FiltersToMatchingTitle_IsOk`) locks in the Movie fix.
`AlbumResourceTest.AlbumResourceSearch_FiltersToMatchingTitleOrArtist_IsOk` (added 2026-07-07) now locks in the Album fix too, closing the gap this finding originally flagged.

Files:

- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/AlbumRepository.cs`

## CarHistory treated a car ID as free text, and CarRepository's search never covered the field that actually exists on a Car document

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
