# AutoMapper removal and replacement plan

## Why

AutoMapper is no longer permissively licensed: since v15 (July 2025) it belongs to Lucky Penny Software and is dual-licensed, either the Reciprocal Public License 1.5 (RPL-1.5) or a commercial license.
RPL-1.5 is an aggressive copyleft license: using AutoMapper under it obligates Keeptrack itself to be licensed and published under RPL-1.5, which is incompatible with Keeptrack's own PolyForm Strict 1.0.0 license.
Until this removal ships, Keeptrack relies on AutoMapper's commercial "Community" tier (free below $5M revenue), which keeps the project bound to a third party's licensing terms and enforcement mechanism (license keys).
AutoMapper 16.2.0 is currently the only non-permissive dependency in `Directory.Packages.props`; every other package is MIT, Apache-2.0, BSD-3-Clause or MS-PL.
Removing it therefore ends the last third-party licensing constraint on Keeptrack.
It is also a quality win: the `AllowNullDestinationValues = false` behavior has caused at least four documented production bugs (see CLAUDE.md and `docs/code-quality-findings.md`).

## Replacement choice

Replace AutoMapper with [Riok.Mapperly](https://github.com/riok/mapperly) (Apache-2.0, actively maintained, v4.x), a compile-time source generator with no runtime reflection.

Alternatives considered:

- Fully hand-written mapper classes: zero dependencies, but no compile-time drift detection - adding a property and forgetting to map it fails silently, the class of bug `AutoMapperConfigurationTest` exists to catch today.
- Mapster: MIT-licensed but maintenance has stalled, and it is runtime-reflection based like AutoMapper, so it keeps the same "invalid configuration only fails at runtime" weakness.

Mapperly wins because unmapped members surface as build diagnostics (`RMG012`/`RMG020`), which is a strictly stronger guarantee than the current runtime `AssertConfigurationIsValid` test.
Bespoke mappings that don't fit attribute configuration (Car's flattening) are hand-written as ordinary methods inside the same mapper class, which Mapperly supports natively.

## Target architecture

AutoMapper's single untyped `IMapper` is replaced by two small in-house interfaces, so the generic base classes stay generic:

- `Infrastructure.MongoDb`: `IStorageMapper<TModel, TEntity>` with `TEntity ToEntity(TModel model)`, `TModel ToModel(TEntity entity)` and `List<TModel> ToModels(List<TEntity> entities)`.
- `WebApi`: `IDtoMapper<TDto, TModel>` with `TModel ToModel(TDto dto)` and `TDto ToDto(TModel model)`.

`MongoDbRepositoryBase<TModel, TEntity>` takes `IStorageMapper<TModel, TEntity>` instead of `IMapper`; `DataCrudControllerBase<TDto, TModel>` takes `IDtoMapper<TDto, TModel>` instead of `IMapper`.
Each entity type gets one `[Mapper]` partial class per boundary (e.g. `BookStorageMapper : IStorageMapper<BookModel, Book>` and `BookDtoMapper : IDtoMapper<BookDto, BookModel>`).
All mappers are registered as singletons in the existing DI extension methods.
Storage mappers move into `Infrastructure.MongoDb/Mappers/` - they map entities to Domain models, so they belong in the project that owns both types.
They only live in `WebApi` today because `AddAutoMapper` is app-level wiring.
DTO mappers live in `WebApi/Mappers/`, replacing `WebApi/MappingProfiles/`.
The owner-less reference repositories inject their concrete mapper class directly - they are purpose-built already and need no shared abstraction.
This covers `TvShowReferenceRepository`, `MovieReferenceRepository`, `BookReferenceRepository`, `VideoGameReferenceRepository`, `AlbumReferenceRepository` and `PersonReferenceRepository`.
Read-only feature controllers (`WatchNextController`, `WishlistController`, `ReferenceDataController`, `CarController`'s metrics, `HouseController`'s metrics) get small one-directional Model-to-DTO mapper classes following the same pattern.
`PagedResult<T>.Map` in `Common.System` takes a plain delegate and needs no change.

## Behavioral decisions

### Drop `AllowNullDestinationValues = false` (the central decision)

AutoMapper is configured so that a null source string maps to `""` and a null source object maps to a new all-default instance.
Mapperly preserves nulls, which is the honest semantics this codebase has repeatedly patched its way back toward.
The evidence: the `FindOneAsync` 404 guard, the `ReferenceMatch.Creator` alias duplication, the `NextMaintenance` `AllowNull()`, and the `Coordinates` `AllowNull()`.
The migration deliberately adopts null-preserving semantics instead of replicating the old behavior.

Consequences to handle:

- New writes will omit unset string fields entirely (the codebase-wide `IgnoreIfNullConvention(true)` already does this for null properties) instead of storing `""`; old documents keep their stored `""` values.
- Every "is this string field unset" query must match null or empty - `UnresolvedFilter()` already does; audit for any other `Eq(field, "")` or `Eq(field, null)` unset-checks and align them.
- Explicit `ReferenceId = ""` assignments (the "clear the link" path in `TryLinkExisting*ReferenceAsync`) are plain code, not mapping behavior, and stay as-is.
- The `ReferenceMatch.Creator` and `CarHistoryLocation.Coordinates` `AllowNull()` opt-outs become dead configuration and are deleted; keep `UpsertAsync_PersistsANullCreator_AsAnActualBsonNullNotAnEmptyString` as the regression guard.
- The `entity is null` guards in `FindOneAsync` and the reference repositories' `Find*Async` methods stay: Mapperly throws on a null source, so the guards remain the only correct "not found" handling.

### Nullable DTO members mapping to `required` model members

`BookDto.Title` is nullable while `BookModel.Title` is `required` non-nullable (the `InventoryPageBase` `new()`-constraint gotcha), and AutoMapper silently substituted `""` today.
Mapperly refuses to compile this silently, which forces an explicit per-member decision.
For exact behavior parity, map these members with an explicit `?? string.Empty` user mapping in the affected DTO mappers first.
Tightening this to a real 400 validation error for a missing title is a worthwhile follow-up, but a separate change - don't mix a behavior change into the mechanical migration.

### Enum mapping between Domain and Contracts

Domain enums and their Contracts duplicates (`TvShowStatus`, `CarHistoryType`, `CarEnergyType`, `HouseEventType`, `ReferenceItemType`) are mapped by name today via AutoMapper's automatic enum-by-name convention.
Set `EnumMappingStrategy = EnumMappingStrategy.ByName` on the DTO mappers' `[Mapper]` attribute.
This upgrades the guarantee: a member-name drift between the two enum definitions becomes a build diagnostic instead of a runtime surprise.

### `DateOnly` <-> `DateTime` UTC conversion

The global converter pair in `DataStorageMappingProfile` becomes a shared static class (e.g. `CommonStorageMappings`) with two `[UserMapping]` methods.
Each storage mapper that needs it attaches it via `[UseStaticMapper(typeof(CommonStorageMappings))]`.
The `DateTimeKind.Utc` stamping must be preserved exactly - the Mongo driver's `DateTimeSerializer` requires it.

### Car's bespoke flattening

`CarDataStorageMappingProfile`'s `CarHistory` mapping (Location/Fuel/Station sub-documents, coordinate array packing, `DateTime.SpecifyKind` UTC stamping) is hand-written rather than translated to attribute configuration.
The hand-written method bodies live inside `CarHistoryStorageMapper` as ordinary C#.
The logic is bespoke enough that explicit C# is more readable than attribute soup, and Mapperly supports mixing hand-written and generated methods in one mapper class.
The null-coordinates semantics (never persist an empty list, only a 2-element list or nothing) must be preserved - `CarHistoryResourceTest` covers the round-trip.

### Member ignores

- `OwnerId` on every DTO-to-Model map: `[MapperIgnoreTarget(nameof(IHasIdAndOwnerId.OwnerId))]`, preserving the "OwnerId is set server-side from claims, never from client input" rule.
- `VideoGameModel.Platform`/`State` on the entity-to-model map: `[MapperIgnoreTarget]`, same as today's `ForMember` ignores.
- `TvShowReferenceDto`/`MovieReferenceDto.Cast`, `BookReferenceDto.AuthorName`/`AuthorImageUrl`, `AlbumReferenceDto.ArtistName`/`ArtistImageUrl`: `[MapperIgnoreTarget]` - these stay hydrated by `ReferenceDataController` joins.

## Migration phases

Each phase builds, passes the full test suite (including integration tests against a real MongoDB), and is independently committable.
`AddAutoMapper` stays registered until the last profile is deleted, so both systems coexist during the migration.

### Phase 1: storage boundary (Infrastructure.MongoDb)

1. Add the `Riok.Mapperly` package to `Directory.Packages.props` and `Infrastructure.MongoDb.csproj`.
2. Add `IStorageMapper<TModel, TEntity>` and `CommonStorageMappings`.
3. Implement one storage mapper per entity pair currently in the three `*DataStorageMappingProfile` classes (about 20 pairs, including embedded types like `Episode`, `ReferenceMatch` and `CastMember`).
4. Switch `MongoDbRepositoryBase` and the six owner-less reference repositories from `IMapper` to the new mappers, updating every repository's primary constructor.
5. Register the mappers in `InfrastructureServiceCollectionExtensions`.
6. Delete the three `*DataStorageMappingProfile` classes.
7. Run the integration test suite against a real MongoDB - the codebase's own history says serialization-level regressions (null vs `""`, missing UTC kind) are only catchable there, never by mocked unit tests.

### Phase 2: web boundary (WebApi)

1. Add `IDtoMapper<TDto, TModel>` and implement one DTO mapper per pair currently in `WebServiceMappingProfile` (about 15 CRUD pairs plus the one-directional WatchNext, Wishlist, Car metrics, House metrics and reference-data maps).
2. Switch `DataCrudControllerBase`, every per-type controller, `WatchNextController`, `WishlistController` and `ReferenceDataController` to the new mappers.
3. Register the mappers in the WebApi DI wiring.
4. Delete `WebServiceMappingProfile`.
5. Run the full test suite again, plus a manual pass over one detail page per domain, a TV Time import, and the Car/House metrics endpoints.

### Phase 3: removal and hardening

1. Remove the `AddAutoMapper` call and the `AllowNullDestinationValues` configuration from `WebApi/Program.cs`.
2. Remove `global using AutoMapper;` from `WebApi/GlobalUsings.cs` and the remaining `using AutoMapper;` directives.
3. Remove the `AutoMapper` package reference from `Directory.Packages.props`, `WebApi.csproj`, `Infrastructure.MongoDb.csproj` and `WebApi.IntegrationTests.csproj` (the last is vestigial - tests resolve repositories through DI).
4. Delete `AutoMapperConfigurationTest` - its job is now done at compile time.
5. Escalate Mapperly's unmapped-member diagnostics (`RMG012`, `RMG020`) to errors in `.editorconfig`, so configuration drift fails the build the way the deleted test used to fail the run.
6. Update CLAUDE.md: rewrite the `AllowNullDestinationValues` gotchas for the new null-preserving semantics, and update the "Adding a new trackable item type" checklist (step 6 becomes "add a storage mapper and a DTO mapper").
7. Update `CONTRIBUTING.md` and `docs/code-quality-findings.md` where they reference AutoMapper.

## Out of scope

- No MongoDB data migration is required: old documents with `""` values stay readable, and the null-or-empty query pattern covers both generations of data.
- An optional cleanup script normalizing stored `""` to unset (same run-once style as `migrate-poster-url-to-image-url.js`) can follow later but is not a prerequisite.
- Turning the missing-required-title case into a 400 validation error is deferred (see above).
- The project's own relicensing to PolyForm Strict 1.0.0 has already happened (see `LICENSE`); this removal ends the interim reliance on AutoMapper's Community tier.
