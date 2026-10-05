# Data model

How data is shaped and stored across the three layers, and the MongoDB gotchas that only a real database reveals.

## Three classes per entity

Every user-owned entity implements `IHasIdAndOwnerId` at all three layers, one class each: a Domain model, a MongoDB entity and a DTO.
Duplicated data shapes are expected, duplicated logic over them is not.

Mapping is compile-time through [Riok.Mapperly](https://github.com/riok/mapperly): one `[Mapper]` partial per pair in `Infrastructure.MongoDb/Mappers/` (`IStorageMapper<TModel, TEntity>`) and `WebApi/Mappers/` (`IDtoMapper<TDto, TModel>`).
Mapperly was chosen because an unmapped member is a build diagnostic rather than a runtime surprise, and because it has no reflection and a permissive license.
Hand-written mappers would let a forgotten property fail silently, and runtime mappers only fail when the mapping runs.

- **An unmapped member is a build error** (`RMG012`/`RMG020` escalated in `.editorconfig`).
  A member a direction genuinely does not need gets an explicit `[MapperIgnoreSource]`/`[MapperIgnoreTarget]`.
- **Mapping preserves nulls.**
  A null string stays null, and `IgnoreIfNullConvention` omits it from the stored document.
- `OwnerId` uses `[MapValue(nameof(Model.OwnerId), "")]` from DTO to model (a plain ignore does not compile, it is `required`).
  `DataCrudControllerBase` overwrites it from the caller's claims, so it is never trusted from client input.
- Read-only feature controllers (`WatchNextController`, `WishlistController`, Car and House metrics, `ReferenceDataController`) use a small one-directional model to DTO mapper injected by its concrete type, and so do the owner-less reference repositories.
- Bespoke shapes are hand-written methods inside the mapper class, as in `CarHistoryStorageMapper`, which never persists an empty coordinates list: two values or nothing.

### Enums

An enum used in a Domain model needs a separate copy in `WebApi.Contracts`, since Contracts does not depend on Domain.
Member names stay identical and DTO mappers set `EnumMappingStrategy.ByName`, so drift becomes a build diagnostic.
MongoDB entities reuse the Domain enum directly.

`ImportMediaType` and `CopyType` exist in both namespaces, so a controller importing both aliases one.

### Required members

**A DTO used by `InventoryPageBase<TDto>` can never have a `required` member.**
That base is constrained `where TDto : IHasId, new()`, and any `required` member breaks `new()` (`CS9040`).
That is why `BookDto.Title`, `CarDto.Name` and similar are nullable while their models are `required`, and why DTOs with no `InventoryPageBase` usage (`CarHistoryDto`) mirror `required` in full.

A nullable DTO member mapping to a `required` model member needs an explicit fallback: `CommonDtoMappings.ToRequiredString`, attached through `[UseStaticMapper]`.
`CarDto.EnergyType` (nullable, and a different enum type) has its own hand-written `[UserMapping]` wrapping the generated `ByName` conversion.

### Naming

Never name a property bare `Type`: discriminators are `CarHistoryModel.EventType`, `HouseEventType`, `HealthEventType`, `TvShowModel.State`.

## Storage

**A single-word property is stored camelCase, not snake_case**: `CamelCaseElementNameConvention` is registered globally in `InfrastructureServiceCollectionExtensions`, so only multi-word members carry an explicit `[BsonElement("public_reimbursement")]`.
Repository code names fields with **expressions**, which resolve through the class map.
Anything written by hand against raw names uses the stored name: an index or a `$rename` naming `Specialty` instead of `specialty` matches zero documents and reports success.

`DateOnly` values are stored as UTC `DateTime` through `CommonStorageMappings`, since the driver's serializer requires the UTC kind.

### Lookups that find nothing

**Every `Find*Async` that can find nothing checks `entity is null` before mapping**, `MongoDbRepositoryBase.FindOneAsync` included, since Mapperly throws on a null source and "not found" would become an exception instead of a 404.

`MongoDbRepositoryBase` treats an id that is not a valid ObjectId as naming no document, instead of the driver's `FormatException` becoming a 500 (`MalformedIdResourceTest`).

### "Unset" is null or empty

Documents written before Mapperly store unset strings as `""`, so `Eq(x => x.ReferenceId, null)` misses them.
Any "is this string field unset" query copies `UnresolvedFilter()` from `TvShowRepository`/`MovieRepository`, which matches null, missing and empty.

### Search

Every `GetFilter` searches with a regex `Contains`, which a text index never speeds up, so the index script declares no text index.
Each entity searches the fields that make sense for it, with no shared search contract: `Book` searches title, series and author, `VideoGame` adds exact filters on platform and state, `TvShow` and `Movie` search the title only.

- **MongoDB allows one `$text` per query**, so a child's parent id is filtered with `Eq`, never `Text`, or a free-text search alongside it throws.
- **A `$text` filter rejects a collation**, and the title sort attaches one, so a repository moving to `$text` must gate the collation.
- **A `GetFilter` override combines with `filter &=`**, or its condition is built and silently dropped.

### List ordering

`MongoDbRepositoryBase.FindAllAsync` sorts every page, defaulting to `_id` descending with `_id` as the tie-break under every other key, since an unsorted skip and limit can duplicate or drop items across pages.
`PagedRequest.Sort` carries a `ListSort` key (`title`, `rating`), and a repository opts in by overriding `SortTitleField`/`SortRatingField` with an expression (`Car.Name` is stored as `commercial_name`).
The title sort attaches a per-query `Collation` ("en", strength 2).

`PageSize` has no upper bound, since detail pages ask for one large page to load all of a parent's children (see [backlog](backlog.md)).

### Indexes

`scripts/mongodb-create-index.js` declares every index and is idempotent.

- **Every tenant collection has a plain `owner_id` index**, since every list query filters on it first.
  A partial index such as `movie_favorite` does not serve a plain list query, since the planner only uses it when the query repeats the partial filter.
- **An index names the stored field**: `Car.Name` is stored as `commercial_name`, so an index on `title` covers nothing.
- Partial indexes serve sparse flags, and unique indexes enforce natural keys.

## Child entities

`CarHistory`/`Car`, `Episode`/`TvShow`, `HouseHistory`/`House`, `HealthRecord`/`HealthProfile` are separate top-level collections referencing the parent by id (`car_id`, `tv_show_id`), not embedded arrays.
They grow without bound per parent, and features query them across all of a user's parents at once (Watch Next), which needs a plain indexed query rather than `$unwind`.
Only small, always-together, never-queried-alone data is embedded (`TvShowReferenceModel.Episodes`: bounded, always fetched whole).

**Every parent cascades its delete**: its controller overrides `OnDeletedAsync` and calls the child repository's `DeleteAllFor<Parent>Async`, a one-liner over `MongoDbRepositoryBase.DeleteAllByParentAsync` taking the parent-id expression.
A child is only reachable through its parent id, so it would otherwise be orphaned forever.
Each cascade has a real-MongoDB `*ResourceTest` case, since a mocked repository cannot prove the filter matches.

A malformed id passed as a child filter (`GET /api/episodes?TvShowId=not-an-object-id`) still returns a 500, and no UI path reaches it.

## Migrations

**A data-shape rename needs an idempotent migration script** (`scripts/migrate-*.js`, a `$rename` or equivalent, followed by a re-run of the index script), not just updated `[BsonElement]` attributes, or every existing document silently loses the field.
A C# rename that keeps the stored element name (`[BsonElement("status")]` on `State`) needs none.
How to run them is in [Operations](operations.md).

## Adding a trackable type

`Book`, `Movie`, `Album`, `TvShow`, `VideoGame` and `Car` are the templates, and a new type touches every layer:

1. `Domain/Models/<X>Model.cs` and `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` and `Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs`, whose XML doc comments feed the OpenAPI spec.
4. `WebApi/Controllers/<X>Controller.cs`, a one-line class extending `DataCrudControllerBase<TDto, TModel>`.
5. The repository and storage mapper registered in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`, the DTO mapper in `Program.cs`.
6. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` (extends `InventoryApiClientBase<TDto>`) and `Pages/<X>.razor`/`.razor.cs` (extends `InventoryPageBase<TDto>`, overrides `ListRoute`).
   The Add form carries only identity fields, everything else is edited on the detail page, which starts with a `<Breadcrumb/>`.
   List rows are uniform media rows rendered by `InventoryList`, the whole row opens the detail page, and there is deliberately no per-row edit modal.
7. Indexes in `scripts/mongodb-create-index.js`: natural-key uniqueness, query shapes, partial indexes for sparse flags.
8. If reference-linked: the DTO implements `IReferenceLinkedDto` (server-hydrated `ImageUrl`, ignored both ways in the mapper), the reference repository gets a batched `FindByIdsAsync`,
   and the controller overrides `OnListMappedAsync` to hydrate covers through `ReferenceImageHydrator`, one batched lookup per page, never one per item.
9. A `[Authorize]` policy matching the [free tier](architecture.md#free-preview-tier), and its row in `FreeTierTest`.
10. A share category, if the type should be shareable (see [Sharing](sharing.md)).
