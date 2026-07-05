# Code quality findings

This document tracks a code review performed on 2026-07-06 against current .NET and MongoDB best practices.
Each finding is classified as a confirmed bug, a confirmed by-design behavior, or a known gap that is not yet implemented.
Update this file as items are fixed or as new reviews are performed.

## Confirmed bugs

These are true defects. They should be fixed.

### Search is a no-op for Movie and Music Album

`MovieRepository.GetFilter` and `MusicAlbumRepository.GetFilter` build a MongoDB filter with `builder.Where(...)`.
The result is never combined into the returned `filter`.
As a result, the `search` box on the Movies and Music Albums pages currently filters nothing.

Files:

- `src/Infrastructure.MongoDb/Repositories/MovieRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/MusicAlbumRepository.cs`

Fix: combine the built expression back into the filter, e.g. `filter &= builder.Where(...)`.

### Car and CarHistory search relies on a `$text` index that does not exist

`CarRepository` has no `GetFilter` override, so it falls back to `MongoDbRepositoryBase.GetFilter`, which calls `builder.Text(search)`.
`CarHistoryRepository.GetFilter` also calls `builder.Text(...)`.
Both require a MongoDB text index on their collection.
`scripts/mongodb-create-index.js` only creates text indexes for `book`, `movie`, `tvshow`, and `videogame`.
No index exists for `car` or `car_history`.
A search request against either resource will throw a runtime error ("text index required for $text query").

Files:

- `src/Infrastructure.MongoDb/Repositories/CarRepository.cs`
- `src/Infrastructure.MongoDb/Repositories/CarHistoryRepository.cs`
- `scripts/mongodb-create-index.js`

Fix: either create the missing indexes, or switch these two repositories to the same per-field filter strategy used by Book/TvShow/VideoGame.

### CarHistory treats a car ID as free text

`CarHistoryRepository.GetFilter` calls `builder.Text(input.CarId)`.
A car ID is an exact identifier, not a free-text search term, so this is the wrong filter type regardless of the missing index above.
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

Only `Book` and `Movie` have integration tests (`BookResourceTest`, `MovieResourceTest`).
`CarHistory`, `MusicAlbum`, `TvShow`, and `VideoGame` have none.
No test exercises the `search` query parameter for any resource, which is why the search bugs above went unnoticed.
No test asserts ownership isolation (that user A cannot read, update, or delete user B's record).
There is no test project for `BlazorApp`.
`BookResourceTest` and `MovieResourceTest` are also close to copy-pasted; a generic/parameterized test base (mirroring `DataCrudControllerBase<TDto, TModel>` on the production side) would cover all resources without duplicating the test code per type.
