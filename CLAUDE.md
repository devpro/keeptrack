# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Keeptrack is a source-available application (PolyForm Strict 1.0.0, see `LICENSE` - not open source).
It lets users save and review everything they read, watch, listen to or play (books, movies, TV shows, music albums, video games, cars/car history).

It is a three-tier .NET 10 / C# solution:

- Frontend: `BlazorApp`, a Blazor Server application.
- Backend: `WebApi`, an ASP.NET Web API (REST).
- Database: MongoDB.

## Commands

```bash
# restore and build the whole solution
dotnet restore
dotnet build

# run the Web API (https://localhost:5011/)
dotnet run --project src/WebApi

# run the Blazor Server app (https://localhost:5021/)
dotnet run --project src/BlazorApp

# run all tests (uses the Microsoft.Testing.Platform runner, xunit v3)
dotnet test

# run a single test project
dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj

# run a single test by fully qualified name
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.Services.WatchNextServiceTest.ComputeInProgressShows_IncludesShowWithAConfirmedAiredUnwatchedNextEpisode"

# build container images
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```

A local MongoDB instance is required to run the Web API or the integration tests:

```bash
docker run --name mongodb -d -p 27017:27017 mongo:8.2
```

Integration tests also need Firebase test-user credentials and MongoDB connection settings.
Provide them as environment variables, or in a `Local.runsettings` file at the repository root (see `CONTRIBUTING.md` for the template).
Never commit this file.

## Architecture

The solution follows a layered / clean-architecture style split across small, single-purpose projects (`src/*`), with `Domain` at the center and no project referencing "outward":

Project                  | Depends on                                             | Responsibility
-------------------------|--------------------------------------------------------|---------------
`Common.System`          | —                                                      | Cross-cutting primitives shared by every layer: `IHasId`, `IHasIdAndOwnerId`, `PagedRequest`, `PagedResult<T>`.
`Domain`                 | `Common.System`                                        | Business models (`*Model` in `Models/`) and repository interfaces (`I*Repository` in `Repositories/`). No persistence or web concerns.
`Infrastructure.MongoDb` | `Domain`                                               | MongoDB implementation: BSON `Entities/` and `Repositories/` implementing the `Domain` interfaces.
`WebApi.Contracts`       | `Common.System`                                        | Public REST DTOs (`Dto/`), shared between `WebApi` and `BlazorApp` so the Blazor client can deserialize API responses without duplicating classes.
`WebApi`                 | `Infrastructure.MongoDb`, `Domain`, `WebApi.Contracts` | ASP.NET Web API: controllers, DTO mappers, DI wiring, JWT authentication, OpenAPI/Scalar docs.
`BlazorApp`              | `Common.System`, `WebApi.Contracts`                    | Blazor Server UI. Talks to `WebApi` over HTTP using the shared DTOs; it never references `Domain` or `Infrastructure.MongoDb` directly.

### Data model conventions

Every entity that belongs to a user implements `IHasIdAndOwnerId` (`Id` + `OwnerId`) at all three layers (`Domain` model, MongoDB entity, contract DTO), each with its own class.
Mapping between them is generated at compile time by [Riok.Mapperly](https://github.com/riok/mapperly) (a source generator, no runtime reflection) rather than AutoMapper - see `docs/automapper-removal-plan.md` for the removal history:

- `Infrastructure.MongoDb/Mappers/`: one `[Mapper]` partial class per entity pair (e.g. `BookStorageMapper`), implementing `IStorageMapper<TModel, TEntity>` (`Infrastructure.MongoDb/Mappers/IStorageMapper.cs`) - MongoDB entity <-> Domain model.
  Injected into `MongoDbRepositoryBase<TModel, TEntity>` and the six owner-less reference repositories.
- `WebApi/Mappers/`: one `[Mapper]` partial class per CRUD pair (e.g. `BookDtoMapper`), implementing `IDtoMapper<TDto, TModel>` (`WebApi/Mappers/IDtoMapper.cs`) - DTO <-> Domain model.
  `OwnerId` is always set via `[MapValue(nameof(Model.OwnerId), "")]` on the DTO -> model direction (not `[MapperIgnoreTarget]` - `OwnerId` is `required` on the model, so a plain ignore would fail to compile the generated object initializer).
  The placeholder value is immediately overwritten server-side from the authenticated user's claims in `DataCrudControllerBase`, never trusted from client input.
  Read-only feature controllers (`WatchNextController`, `WishlistController`, `CarController`/`HouseController`'s metrics, `ReferenceDataController`) use a small one-directional Model-to-DTO mapper class instead (e.g. `CarMetricsDtoMapper`).
  It's injected as its concrete type rather than through `IDtoMapper`, since it has no DTO -> Model direction to speak of.

Unmapped members are build errors, not a runtime assertion: `RMG012`/`RMG020` (Mapperly's unmapped-target/unmapped-source diagnostics) are escalated to `error` severity in `.editorconfig`.
So a new property added to a model/entity/DTO without a matching mapping fails the build immediately.
This replaced the old `AutoMapperConfigurationTest`'s runtime `AssertConfigurationIsValid()` check, now enforced at compile time instead.
A source-only member each direction doesn't need (like `OwnerId` on the Model -> Dto direction, or a filter-only DTO/model field with no entity counterpart) needs an explicit `[MapperIgnoreSource]`/`[MapperIgnoreTarget]` attribute.
This satisfies the diagnostic.
Don't leave a member unmapped and unignored - the build won't compile.

An enum used in a `Domain` model (e.g. `TvShowModel.State: TvShowStatus?`) needs its own **separate** definition in `WebApi.Contracts` (`TvShowDto.State` uses `Keeptrack.WebApi.Contracts.Dto.TvShowStatus`, not the Domain one).
`WebApi.Contracts` doesn't depend on `Domain` (see the project table above), so the DTO can't reference the Domain enum directly.
Keep the member names identical between the two; the DTO mapper sets `EnumMappingStrategy = EnumMappingStrategy.ByName` on its `[Mapper]` attribute so Mapperly maps enum-to-enum by name.
This generates a build diagnostic (rather than a silent runtime mismatch) if a member name ever drifts between the two definitions.
The Mongo entity, on the other hand, *can* reuse the Domain enum directly (`Infrastructure.MongoDb` depends on `Domain`).
Only the Contracts layer needs the duplicate, and storage mappers don't need the `ByName` strategy since there's only one enum type involved.

**Gotcha:** a DTO member that's nullable while its model counterpart is `required` non-nullable (the `InventoryPageBase` `new()`-constraint gotcha two sections down - e.g. `BookDto.Title` vs. `BookModel.Title`).
This needs an explicit fallback on the DTO -> model direction.
Mapperly refuses to compile a silent substitution the way AutoMapper used to.
`CommonDtoMappings.ToRequiredString` (`WebApi/Mappers/`, a `[UserMapping]` static method attached to the affected DTO mappers via `[UseStaticMapper(typeof(CommonDtoMappings))]`) reproduces AutoMapper's old `?? string.Empty` behavior.
It applies for every such string member across every mapper that needs it.
This is for exact behavior parity.
Tightening this to a real 400 validation error for a missing title is a deliberate follow-up, not part of the mechanical migration.
`CarDto.EnergyType` (nullable) -> `CarModel.EnergyType` (required, non-nullable, and a *different* enum type than the Dto's) needs the same treatment but can't reuse `ToRequiredString` (wrong types).
See `CarDtoMapper`'s own hand-written `[UserMapping]` for the pattern: a partial method gets the generated, drift-checked `ByName` enum conversion, wrapped by one small hand-written method that only handles the null -> `default` fallback.

### Adding a new trackable item type

Follow the existing types (`Book`, `Movie`, `Album`, `TvShow`, `VideoGame`, `Car`/`CarHistory`) as the template.
A new type touches every layer:

1. `Domain/Models/<X>Model.cs` and `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` (BSON attributes, `snake_case` element names via `[BsonElement]`).
   `Infrastructure.MongoDb/Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs` (XML doc comments drive the generated OpenAPI spec).
4. `WebApi/Controllers/<X>Controller.cs`: a one-line class extending `DataCrudControllerBase<TDto, TModel>` — CRUD logic is never duplicated per controller.
5. Register the repository in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`.
6. Add a storage mapper (`Infrastructure.MongoDb/Mappers/<X>StorageMapper.cs`, implementing `IStorageMapper<TModel, TEntity>`, registered in `InfrastructureServiceCollectionExtensions.cs`).
   Also add a DTO mapper (`WebApi/Mappers/<X>DtoMapper.cs`, implementing `IDtoMapper<TDto, TModel>`, registered in `Program.cs`).
7. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` extending `InventoryApiClientBase<TDto>`, plus a `Pages/<X>.razor` / `<X>.razor.cs` pair extending `InventoryPageBase<TDto>`.

**Gotcha:** `<X>Dto` can never have a `required` member if `Pages/<X>.razor.cs` extends `InventoryPageBase<TDto>` — that base class is constrained `where TDto : IHasId, new()`.
A type with *any* `required` member can't satisfy a bare `new()` constraint in C# (`CS9040`).
This is why `BookDto.Title`, `CarDto.Name`, etc. are all nullable even though their Domain model counterpart (`BookModel.Title`, `CarModel.Name`) is `required`.
It's a hard language limitation forced by the generic list-page base class, not a design inconsistency to "fix" by making the Dto match the model.
A Dto with no `InventoryPageBase` usage (e.g. `CarHistoryDto`, owned-by-a-parent types managed from their parent's detail page rather than their own list page) has no such constraint.
It can mirror the Domain model's `required` members in full.

### Child entities (1-to-many owned by another entity)

`CarHistory` (owned by `Car`) and `Episode` (owned by `TvShow`) are separate top-level collections referencing their parent by id (`car_id`, `tv_show_id`), not embedded arrays.
This is deliberate MongoDB schema design, not an accident: these child collections can grow unbounded per parent over years of use.
Features that need to query the child across *all* of a user's parents at once (e.g. Watch Next, below) need a plain indexed query rather than an `$unwind` aggregation.
Embedding is the right call for genuinely small, always-together, never-queried-alone data; neither condition holds here.
`EpisodeRepository.GetFilter`/`CarHistoryRepository.GetFilter` both filter their parent-id field (`TvShowId`/`CarId`) with `Eq`, not `Text`.
An exact-id filter used `Text` in `CarHistory`'s first draft, throwing whenever a free-text `search` was also supplied (MongoDB allows only one `$text` expression per query).
This was fixed and is covered by `docs/code-quality-findings.md`.
New multi-word BSON fields get an explicit `[BsonElement("snake_case_name")]`; don't rely on the `CamelCaseElementNameConvention` registered in `AddMongoDbInfrastructure`.
Every existing multi-word field already overrides it explicitly, so it's effectively dead configuration.
Indexes for new collections are declared in `scripts/mongodb-create-index.js` (natural-key uniqueness, query-shape support, and partial indexes for sparse boolean flags like `is_favorite`/`want_to_watch`).

`CarHistoryModel.EventType` (`CarHistoryType`: `Refuel`/`Maintenance`/`Other`) is a real discriminated enum, not free text.
This follows the same "never name a property/field bare `Type`" rule as any other discriminator in this codebase (see `TvShowModel.State`'s own rename history above).
A bare `Type` reads ambiguously and collides in spirit with `object.GetType()`/`System.Type`.
`Car.EnergyType` (`CarEnergyType`: `Combustion`/`Hybrid`/`Electric`) and `CarHistoryModel.EventType`/`CarId`/`HistoryDate` are all `required` on both the Domain model and the Mongo entity.
`CarDto` itself can't mirror `Name`/`EnergyType` as `required`, because `Cars.razor` extends `InventoryPageBase<CarDto>`, which needs a bare `new()` constraint — a type with *any* `required` member can't satisfy `new()` in C#.
So the Dto layer stays nullable there by hard language necessity, not by choice (`CarHistoryDto` has no such constraint, so it mirrors `required` in full).
`CarHistoryModel.DeltaMileage` is real user-entered data (typically read off the car's own trip computer at refuel time), not a derived/computed field.
It's kept specifically so `Domain/Services/CarMetricsService.cs` can cross-check it against consecutive `Mileage` readings and flag a likely typo or a skipped entry.
This is the automated version of a manual spreadsheet cross-check, and the reason this field was kept rather than dropped as "unused" during review.
`CarMetricsService` (consumption — only ever computed across a full refill/recharge, never a partial one — cost-of-ownership history, mileage warnings, next-maintenance-due) follows `WatchNextService`'s shape.
It's a plain, `AddSingleton`-registered, unit-tested pure computation class with no persistence of its own.
It's exposed via `CarController.GetMetrics` the same way `VideoGameController.RefreshReference` adds an extra per-item action to an entity's own CRUD controller instead of a separate cross-entity controller.

`House`/`HouseHistory` (owned-by-a-parent, same shape as `Car`/`CarHistory` above) is a deliberately smaller sibling, not a second copy of Car's design.
The priority (confirmed with the owner) is an exhaustive, browsable action log for insurance purposes plus a yearly cost review, not fuel/mileage tracking or reminders.
The owner tracks recurring bills/maintenance schedules elsewhere and explicitly asked for reminders to stay out of scope ("keep it simple, not important, I manage it elsewhere").
Concretely: `HouseHistoryModel` has no `Mileage`/`DeltaMileage`/fuel fields, no location sub-fields (a house doesn't move, unlike a car's refuel stops).
`Domain/Services/HouseMetricsService.cs` has no `ComputeNextMaintenanceDue`-style due-date engine - it only computes `ComputeAnnualCostHistory` (cost per year, broken down by `HouseEventType`: `Maintenance`/`Installation`/`Rework`/`Purchase`/`Bill`/`Other`).
`HouseHistoryModel.HistoryDate` stays `DateOnly` (not `DateTime` like `CarHistoryModel.HistoryDate`) - House has no Car-style same-day-multiple-entries ordering need (a road trip's several refuel stops).
So it reuses `CommonStorageMappings` (`Infrastructure.MongoDb/Mappers/`), the shared `DateOnly<->DateTime` UTC-stamping conversion every other date field in the app attaches via `[UseStaticMapper(typeof(CommonStorageMappings))]`, for free.
This avoids Car's bespoke hand-written `DateTime.SpecifyKind`/`ModalTimeText` "HH:mm" proxy machinery.
`HouseHistoryModel.Provider` is a single field (contractor/technician/utility company/store name) covering every category, unlike Car's Refuel-only `StationBrandName` vs. Maintenance-only `Garage` split.
House has no event type where "who was involved" doesn't apply, so one field suffices.

`HouseDetail.razor`'s yearly cost chart is a single-series bar chart (total cost per year) plus a plain HTML breakdown table underneath (rows = years, columns = the 6 categories + total), not a 6-color stacked bar chart.
A stacked chart with that many categories would be visually noisy and add real code, and the table already carries the actual per-category precision an insurance review needs at a glance.
The chart's axis-drawing code (`ChartGeometry`, `RenderAxes`, `EvenlySpacedIndices`) was extracted from `CarDetail.razor` into `src/BlazorApp/Components/Shared/SvgChartHelpers.cs` specifically so House's chart wouldn't duplicate it.
The CLAUDE.md "no duplicated algorithms" quality bar applies to Razor-hosted chart code the same as any other logic.
Only the axis/geometry math moved; each page's own series-drawing loop (Car's stacked 2-series cost bars, Car's single-series consumption line, House's single-series year bars) stays local.
That part differs enough per chart that forcing one shared renderer would have been the over-generalization the quality bar warns against.
The shared CSS these charts need (`.kt-callout*`, `.kt-chart-axis-text`/`-title`, `.kt-chart-svg`, `.kt-sheet-table`, `.kt-chart-legend`/`.kt-legend-swatch`) moved from `CarDetail.razor.css` into `app.css`.
It's now plain global rules, for the same reason.
As a side benefit, they no longer need `::deep` to reach into child `*Row` components' markup, since global (non-isolated) CSS was never scoped to begin with.

### Reference data (shared, owner-less)

`tvshow_reference` and `movie_reference` (`Domain/Models/TvShowReferenceModel.cs`/`MovieReferenceModel.cs`, `Infrastructure.MongoDb/Entities/TvShowReference.cs`/`MovieReference.cs`) hold metadata (synopsis, episode titles) fetched from TMDB.
They are the one deliberate exception to "every collection has `owner_id`": this data is public facts about a real show/movie, not user content.
So storing it once and pointing every tenant's `TvShowModel.ReferenceId`/`MovieModel.ReferenceId` at it avoids duplicating the same show across every user who tracks it.
Matching key is normalized title + year (`TitleNormalizer.Normalize`, `Common.System/TitleNormalizer.cs` — shared with `TvTimeImportService` so the two never drift on what counts as "the same title").
The rest of this section walks through the mechanics using TV shows/movies/TMDB as the concrete example.
`book_reference`/`videogame_reference`/`album_reference` (Open Library/RAWG/Discogs) follow the identical shape - see "Reference data now covers five domains" further down for what's shared versus what's provider-specific.

These repositories (`ITvShowReferenceRepository`/`IMovieReferenceRepository`) do **not** extend `IDataRepository<TModel>` or `MongoDbRepositoryBase<TModel, TEntity>`.
Both are hard-constrained to `IHasIdAndOwnerId` and owner-scoped paged CRUD, which doesn't fit a shared lookup table with a different method set (`FindByTitleYearAsync`, `UpsertAsync`).
Don't force a new owner-less collection through that base; write a small purpose-built repository instead, like these two.

`TvShowReferenceModel.Episodes` is **embedded**, the opposite choice from the per-tenant `Episode` collection.
This isn't inconsistent - the access pattern is opposite too: a reference show's episode list is bounded to its real runtime, always fetched as a whole (rendering a season picker needs all of it at once), and never queried across shows.
That's exactly the case CLAUDE.md already says favors embedding.
The per-tenant `Episode` collection fails all three conditions (unbounded per-user growth, queried across shows for Watch Next, upserted independently), which is why that one is referenced instead.

`WebApi/ReferenceData/ReferenceEnrichmentService.cs` is the single place that resolves a title+year to a TMDB id.
It propagates the result to every tenant's matching document via `ITvShowRepository.SetReferenceLinkAsync`/`IMovieRepository`'s equivalent.
The automatic best-effort match is fired from `TvShowController`/`MovieController`'s `OnCreatedAsync` hook on `DataCrudControllerBase`, and from `TvTimeImportService` after each newly-imported show/movie.
Both it and the admin's manual pick (`ReferenceDataAdminController`) call through this one method.
This avoids duplicating the "upsert reference doc, then propagate" logic.
The automatic path only ever acts on a *single, confident* TMDB search result - zero or multiple candidates leaves the item unresolved for the admin queue rather than guessing.
This is the same "don't guess when you don't have the info" principle as Watch Next, below.
`SetReferenceLinkAsync` sets `ReferenceId`, `Title` (the TMDB canonical name) and, when the reference has one, `Year` (the TMDB canonical year) in the same update.
Linking is meant to correct whatever title/year the tenant originally typed/imported, not just attach an id, and pre-populating `Year` from a trustworthy source beats leaving it at whatever the tenant originally guessed.
`Year` stays freely editable afterward on `MovieDetail.razor`/`TvShowDetail.razor` (same as `Title` - see the paragraph on `TryLinkExistingTvShowReferenceAsync` below for why), so this is a starting value, not a lock.

`TvShowReferenceModel`/`MovieReferenceModel.MatchedAliases` is a `List<ReferenceMatchModel>` of every (title, year) combination ever confirmed (via a TMDB resolution, automatic or admin-picked) to mean this exact show/movie.
This is not just the document's own canonical `TitleNormalized`/`Year`.
`ResolveTvShowAsync`/`ResolveMovieAsync` populate it with **both** the (TMDB canonical title, TMDB canonical year) and whatever (title, year) the tenant actually searched with.
This uses `MergeMatchedAliases`, merged with any aliases a previous resolution already contributed - never overwritten.
`TvShowReferenceRepository`/`MovieReferenceRepository.UpsertAsync` additionally guarantees the document's own (`TitleNormalized`, `Year`) is always in the list even if a caller forgot.
Year travels with its specific title variant rather than living as a single top-level scalar, because a title-only alias list isn't enough on its own.
Two tenants (or a tenant and TMDB's own canonical data) can legitimately record different years for the same real show.
A French-language tenant's "Le Fil" (2002) and an English tenant's "The Wire" (2002) are one case this handles.
So is a tenant who recorded 2003 by mistake and TMDB's canonical year of 2002 - both should still resolve to the same document once *either* variant has been confirmed.
`FindByTitleYearAsync`/`FindByTitleAsync` (on both reference repositories) query `MatchedAliases` with `Builders.Filter.ElemMatch` instead of a plain `Eq` against `TitleNormalized`/`Year`.
Both the title and year condition must hold on the *same* embedded array element - a plain `AnyEq`-per-field approach would let a title match on one alias and a year match on a completely different one.
`scripts/mongodb-create-index.js`'s `tvshow_reference_title_year`/`movie_reference_title_year` indexes were changed to a compound multikey index over `matched_aliases.title`/`matched_aliases.year` accordingly.
A single compound index over two sub-fields of the *same* array is fine, unlike trying to combine two *different* array fields in one compound index, which MongoDB disallows.

`ReferenceEnrichmentService.TryLinkExistingTvShowReferenceAsync`/`TryLinkExistingMovieReferenceAsync` is a second, cheaper resolution path that never calls TMDB.
It only checks whether a matching reference document *already exists* (title+year, falling back to title-only, against `MatchedAliases`).
This backs `POST /api/tv-shows/{id}/refresh-reference`/`/api/movies/{id}/refresh-reference`.
That's a "check for reference match" control shown **unconditionally** on both detail pages (not just when unresolved) to **any** authenticated user, not just admins.
It can never do anything beyond reusing a fact some other tenant (or an admin) already established.
It's unconditional deliberately: `Title` and `Year` are both freely editable at any time.
A tenant who thinks their current link is wrong (two different real movies sharing an identical title is common - year and cast/poster are often the only way to tell them apart) needs to be able to edit either.
They need to be able to re-check *even though something is already linked*.
This is to replace a bad match.
The method does **not** short-circuit on an existing `ReferenceId` for exactly this reason.
When a match is found it updates only this tenant's own document directly (`ITvShowRepository.UpdateAsync`/`IMovieRepository`'s equivalent).
It sets `Year` to the reference's own canonical year alongside `Title` and `ReferenceId` (same rationale as `SetReferenceLinkAsync` above).
This is rather than the broad cross-tenant `SetReferenceLinkAsync` (which refuses to touch already-linked documents by design, so it wouldn't fix a wrong link on this tenant's own item).
But it still also calls `SetReferenceLinkAsync` with the pre-edit title/year afterward, so any other still-unresolved tenant sharing that text benefits too.
When **no** match is found for the current title/year and the document *was* linked, the link is cleared (`ReferenceId` set to `""`) rather than left pointing at something the tenant just told us, by editing the title, is wrong.
Clearing it is also exactly what puts the item back into the admin's unresolved queue (`FindDistinctUnresolvedTitleYearsAsync`) for a manual TMDB search.
This is deliberately explicit/user-triggered rather than automatic on every page view (no `GetById` side effect), so the behavior stays visible and predictable.
It's also why `Title`/`Year` are unconditionally editable on both `MovieDetail.razor`/`TvShowDetail.razor` regardless of link status - free editing is what makes "fix a typo or a wrong year (or pick a different match), then hit refresh" work.
`Year` matters here specifically because TMDB search results embedding a year into the title text (e.g. "Dune 2021") is unreliable - the tip that used to suggest doing that was wrong and has been removed.
The actual matching (both this local lookup and the live TMDB search behind `InlineReferenceLinker`) always takes year as its own separate field/parameter, never parsed out of title text.
The list edit modal (`Movies.razor`/`TvShows.razor`) still locks `Title` for non-admins once linked - that's a separate, intentionally stricter surface for bulk-editing, not an inconsistency to reconcile.

**Gotcha:** the title-only fallback in `TryLinkExistingTvShowReferenceAsync`/`TryLinkExistingMovieReferenceAsync` must run unconditionally, *including* when the tenant's `Year` is `null`.
An earlier version only attempted it when `Year is not null`, which is backwards.
A tenant with no year recorded at all is exactly the case that needs the year-agnostic fallback most, since `FindByTitleYearAsync(title, null)` can only ever match a reference whose own `Year` is also `null`.
Skipping the fallback there meant any linked item with an unset year would unlink itself the instant "check for reference match" was clicked, since neither query could succeed.
Confirmed by a real user hitting this on a genuinely valid, already-linked title.

`ResolveTvShowAsync`/`ResolveMovieAsync`'s "does a reference document already exist for this" check now looks up by TMDB id first.
This uses `ITvShowReferenceRepository`/`IMovieReferenceRepository.FindByExternalIdAsync`, same shape as `IPersonReferenceRepository`'s cast-dedup lookup.
It falls back to title+year/title-only only when no document has that id yet.
Title-text matching alone isn't reliable enough to prevent duplicates.
Two tenants (or an admin resolving the same unresolved queue twice under different title text - a translation, or a typo the admin fixed) can easily resolve the *same* TMDB entry through completely different search strings.
If the existence check only compares title text, the second resolution creates a second reference document for what's genuinely the same movie/show instead of updating the first.
The TMDB id is the one signal that's invariant under any title text difference, so it's checked first and is authoritative.

`scripts/mongodb-create-index.js`'s `tvshow_reference_tmdb_id`/`movie_reference_tmdb_id`/`person_reference_tmdb_id` indexes are `unique: true` with a `partialFilterExpression: { "external_ids.tmdb": { $exists: true } }`.
The application-level id-first dedup check above is what's *supposed* to prevent two documents sharing a TMDB id, but a database constraint is what actually guarantees it can never happen even if a future code path forgets to check.
The partial filter (rather than a plain unique index, or the older `sparse: true` option) is required because it's only `external_ids.tmdb` that must be unique *when present*.
A document from before this field existed (or any owner-less collection document that's never linked to that provider) has no such key at all.
A plain unique index would treat every one of those "missing the field" documents as colliding on the same null key.

Reference data is meant to be portable across environments, not re-earned from TMDB one search at a time per deployment.
`ReferenceDataAdminController`'s `GET/POST /api/reference-data/export`/`import` round-trip the entire `tvshow_reference`/`movie_reference`/`person_reference` collections as a zip of JSON arrays.
Idempotency here is free, not new logic - every repository's existing `UpsertAsync` already replaces-by-id when the model carries one, so re-importing the same export twice is a no-op the second time by construction.
`FindAllAsync()` on each of the three reference repositories exists solely to back this export; it's an unpaged full-collection read, acceptable because this data is small and shared (not per-tenant).

`TvTimeImportService`'s per-show/per-movie reference match (`TryEnrichShowAsync`/`TryEnrichMovieAsync`) fires on its own DI scope via `IServiceScopeFactory`, same shape as `TvShowController`/`MovieController.OnCreatedAsync`.
It's not awaited inline.
A bulk import creating dozens of new shows/movies must not block on a sequential chain of TMDB HTTP calls (search + details + credits, per item) before the import job itself can report "Completed".
If TV Time import feels slow again, check this path before assuming it's a missing Mongo index (already fully audited once - see `docs/code-quality-findings.md`).

**Gotcha (historical - fixed by the AutoMapper -> Mapperly migration, but old data still needs this):** "does this tenant document have no reference link yet" cannot be a plain `Eq(x => x.ReferenceId, null)` filter.
Under AutoMapper, `AllowNullDestinationValues = false` made mapping a model whose string property is null store an **empty string**, never an actual BSON null; documents written that way still exist.
`TvShowRepository`/`MovieRepository`'s `UnresolvedFilter()` matches null *or* empty string for exactly this reason.
Copy that helper's shape (not a bare null check) for any new "is this string field unset" query, even now that new writes store a real null (Mapperly preserves nulls by default).
This one is easy to get wrong silently: it doesn't throw, it just quietly matches zero documents.
A real-MongoDB integration test (`TvShowReferenceLinkingTest`) is what caught it originally, not the unit tests (which mock the repository and never see the actual serialization behavior).

**Second instance of the same gotcha (also historical - see `docs/automapper-removal-plan.md`):** AutoMapper's `AllowNullDestinationValues = false` used to also change `mapper.Map<TDestination>(source)`.
This happened even when `source` itself (not just one of its properties) was `null`.
Instead of returning `null`, it returned a new, all-default instance of `TDestination`.
Mapperly (the current mapper) takes the opposite, honest approach: it *throws* on a null source rather than fabricating a default instance, which is exactly why the `entity is null` guard below still matters, just for a different reason now.
Every `Find*Async` method on `TvShowReferenceRepository`/`MovieReferenceRepository`/`PersonReferenceRepository` does `var entity = await Collection.Find(...).FirstOrDefaultAsync();`.
`entity` can legitimately be null (nothing matched).
Mapping it directly would either fabricate a fake found-but-empty model (old AutoMapper behavior) or throw (current Mapperly behavior).
Neither of those is the `null` that `ReferenceDataController`'s `model is null` 404 check (and anything else checking `is null` on a Find result) needs.
Each of those methods checks `entity is null` before calling the mapper, returning `null` directly instead.
**This isn't limited to the owner-less reference repositories**: `MongoDbRepositoryBase.FindOneAsync` (the shared base every ordinary owner-scoped repository extends) has the exact same shape and needs the exact same guard.
Every entity's `GetById` 404 check depends on it.
Copy this guard for any new Find method that can legitimately return "nothing matched," anywhere in the codebase, not just the owner-less collections.
A mocked-repository unit test cannot catch a regression here, only a real MongoDB integration test can (a mock never exercises the real mapper/serialization behavior).

The reference layer also now has `Genres`, `Cast` (embedded `CastMemberModel` list, pointing at a third owner-less collection, `person_reference`), and `PosterUrl`/`CastMemberDto.ProfileImageUrl`.
Actors are deduplicated across every show/movie that credits them, keyed by TMDB person id via `IPersonReferenceRepository.FindByExternalIdAsync`, not by name.
Images are **hotlinked directly from TMDB's CDN** (`https://image.tmdb.org/t/p/{size}{path}`, built once in `TmdbClient` and stored as a plain URL) rather than downloaded and re-hosted.
This is confirmed to be TMDB's own sanctioned, standard usage pattern (a separate, unauthenticated static-asset host, not the rate-limited API), so there's no local storage/volume/static-file-serving subsystem to operate.
`CastMemberDto` is fully hydrated server-side (`ReferenceDataController` joins the embedded cast list against `person_reference`) specifically because that join needs repository access a generated mapper doesn't have.
`TvShowReferenceDtoMapper`/`MovieReferenceDtoMapper` (`WebApi/Mappers/`) ignore `Cast` via `[MapperIgnoreTarget]` for exactly this reason; don't try to make it a plain mapped member.

`TvShowDetail.razor`'s episode list is a full watch-through checklist (every reference episode, checkbox = watched) once the show has a `ReferenceId`, falling back to the original recorded-episodes-only view with a manual add form when it doesn't.
There's no way to know the full episode count without reference data, so that fallback is a deliberate scope boundary, not a bug.
Checking a box creates an `Episode` with `WatchedAt = today`; unchecking deletes it - there's no way to set an arbitrary watched date from this view once a show is resolved.

Admin-only endpoints (`ReferenceDataAdminController`) use policy-based authorization (`[Authorize(Policy = "AdminOnly")]`, registered in both `WebApi/Program.cs` and `BlazorApp/Program.cs`).
The policy is `RequireClaim("role", "admin")`, backed by a Firebase custom claim.
This is not ASP.NET's built-in `Roles=` support.
Firebase's claim arrives as a plain `"role"` claim rather than the `ClaimTypes.Role` URI that `[Authorize(Roles=...)]`/`<AuthorizeView Roles=...>` expect by default.
`BlazorApp/Components/Account/Controllers/AuthenticationController.cs` copies the `role` claim from the verified Firebase token into the cookie principal at sign-in.
WebApi validates the bearer token's claims directly and needs no equivalent step.
There's no in-app way to grant the first admin; it's a one-off `setCustomUserClaims` call via the Firebase Admin SDK (see `CONTRIBUTING.md`).

**Gotcha:** `WebApi/Program.cs`'s `AddJwtBearer` sets `options.MapInboundClaims = false` deliberately.
Without it, the token handler silently renames certain short JWT claim names to legacy `ClaimTypes.*` URIs before `HttpContext.User` ever sees them.
`"role"` is one of the remapped names (to `ClaimTypes.Role`), so `RequireClaim("role", "admin")` would never match even though the raw token genuinely has a `role` claim.
This is exactly why the Blazor side (whose cookie principal is built by hand in `AuthenticationController`, using the literal claim name) could show the admin nav link while the same request's bearer-token call to WebApi still 403'd.
The two sides were checking different claim types for what was, on the wire, the same claim.
`user_id` was never affected by this because it isn't one of the handful of short names the legacy map remaps; don't assume a new custom claim is equally safe without checking, or just leave `MapInboundClaims = false` alone.

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` (`WebApi/Controllers/DataCrudControllerBase.cs`) implements the full CRUD surface (`GET`, `GET/{id}`, `POST`, `PUT/{id}`, `DELETE/{id}`) once, generically.
It calls the shared `ControllerBaseExtensions.GetUserId()` extension (`WebApi/Controllers/ControllerBaseExtensions.cs`) to read the caller's `user_id` claim, scope every query, and stamp `OwnerId` on writes.
Per-type controllers only need routing and generic type arguments — any new controller (CRUD or not) should call the same extension rather than re-reading the claim.
Unhandled exceptions are converted to JSON error responses by `ApiExceptionFilterAttribute` (`ArgumentException`/`ArgumentNullException` -> 400, everything else -> 500).
It also logs every caught exception via `ILogger<ApiExceptionFilterAttribute>` before converting it - a 500 leaves a server-side trail to diagnose, not just an opaque error in the browser.

**Resilience against failing external providers.** TMDB/RAWG/Open Library/Discogs (`WebApi/ReferenceData/`'s `TmdbClient`/`RawgClient`/`OpenLibraryClient`/`DiscogsClient`) are third-party APIs outside Keeptrack's control.
Slow, rate-limited, or briefly down is a "when," not an "if."
Each of their four `AddHttpClient<...>()` registrations in `Program.cs` chains `.AddStandardResilienceHandler()` (`Microsoft.Extensions.Http.Resilience`).
This gives every call automatic retry, a per-attempt timeout, a total-request timeout, and a circuit breaker.
A transient failure is retried and recovered without the caller ever seeing it.
A provider that's genuinely down fails with a normal exception (mapped to a clean JSON 500 by `ApiExceptionFilterAttribute` above) instead of hanging a request thread indefinitely or degrading the whole app under concurrent load.
Give any future outbound HTTP client to a third-party service the same treatment.
`.AddStandardResilienceHandler()` is a one-line addition to the `AddHttpClient<...>()` chain, not something to hand-roll per client.
Covered by `ExternalProviderResilienceTest` (`test/WebApi.UnitTests/ReferenceData/`), which builds the exact same wiring against a stub `HttpMessageHandler` (no real network).
It asserts both halves: a transient failure is retried and recovered, and a provider that stays down fails cleanly rather than hanging.
This was tested once against `RawgClient` as a representative example, since the wiring is identical for all four and duplicating the same test four times would add nothing.

`builder.Services.Configure<HostOptions>(opts => opts.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore)` in `Program.cs` is a separate, systemic safety net.
By default, an unhandled exception escaping any hosted `BackgroundService.ExecuteAsync` (like `ReferenceSyncBackgroundService`) stops the *entire host*, taking every other endpoint down with it, not just the background job.
`ReferenceSyncBackgroundService`/`ReferenceSyncService` already catch and log everything they can anticipate (see "Keeping reference data fresh" below).
This setting is the backstop for whatever a future background service's own error handling misses.
`Ignore` logs the failure and keeps the rest of the app serving requests instead of crashing the process.
Apply the same reasoning before adding a new `AddHostedService<...>()`: its own `ExecuteAsync` should still catch what it can anticipate (this global setting isn't a substitute for that).
A bug in it should never be able to take down unrelated endpoints.

Not every endpoint is per-item CRUD.
`WatchNextController`/`WishlistController` (read-only cross-entity aggregations) live in `WebApi/Controllers/` like every other controller, with a plain `ControllerBase` rather than being force-fit into `DataCrudControllerBase`.
Their computation lives in `Domain/Services/` (`WatchNextService`, `WishlistService`) since it's pure logic over Domain models with no persistence or web dependency - Domain's stated charter from the project-overview table above.
`WebApi/Import/` (the TV Time GDPR-export upsert, using `CsvHelper` for parsing) and `WebApi/ReferenceData/` still follow the older feature-folder shape (a `ControllerBase` and service class colocated under `WebApi/<Feature>/`).
This is now recognized as the same misplacement `WatchNext` had, but migrating them is deliberately deferred to a separate change to limit regression surface and manual-testing burden.
Don't extend the older feature-folder shape to new code; follow `WatchNextController`/`WishlistController`'s split instead (controller in `Controllers/`, pure computation in `Domain/Services/` when there is any).

`seen_episode_source.csv` alone is a drastically incomplete picture of a user's episode history (it's only written when an episode is marked watched via TV Time's episode-detail screen) - confirmed against real export data, not assumed.
`TvTimeImportService` also reads `tracking-prod-records.csv` and `tracking-prod-records-v2.csv`, TV Time's generic event logs, which capture episodes marked watched any other way (bulk/season actions).
All three are merged and de-duplicated per (show, season, episode), earliest date wins, before upserting `Episode`s.
If a future TV Time export field looks suspiciously sparse, check the raw export files directly (`grep` the show name across every `*.csv`) before assuming the current parser set is complete - this is exactly how the tracking files were found.

`followed_tv_show.csv` is not a complete list of shows either - confirmed with a real show ("The Pitt") that has genuine watch history in the tracking files but no row in `followed_tv_show.csv` at all.
`ImportEpisodesAsync` creates a show on the fly from watch-event data (title, plus the show's TV Time id when the source file has one) rather than skipping shows that aren't already known.
This applies the same rating/favorite/notes enrichment a normally-followed show gets.
Don't reintroduce a "skip if not already followed" check here.

The import is idempotent by matching on a stable, enrichment-immutable id, **not** by title.
Re-running an import used to duplicate every show/movie (and, via the new show id, all their episodes).
Shows/movies were matched by normalized `Title`, but reference enrichment rewrites `Title` to the provider's canonical name after the first import (`SetReferenceLinkAsync`).
So on the second import the export's original title no longer matched and a duplicate was created - confirmed by a real re-import.
The fix stamps every imported show/movie with `TvTimeId` (`IHasTvTimeId`, a real Domain field on `TvShowModel`/`MovieModel` carried through entity/DTO like `ReferenceId`, and round-tripped on edits since `UpdateAsync` is a full `ReplaceOneAsync`).
This is TV Time's own show id for shows (`followed_tv_show.csv`/the tracking logs), and the per-movie tracking `uuid` for movies (every follow/watch/towatch row for one movie shares it).
Movies do have a stable id after all, contrary to the older "movies have no stable id" note, which was only ever true of the per-vote uuid in the rating files.
When the export carries no id for a title (a movie known only from the vote files; a show seen only in `seen_episode_source.csv`), `ResolveTvTimeId` synthesizes a fallback.
It's a deterministic `tvtime_title:<normalized-title>` fallback from the **export** title.
This fallback title is one that enrichment never touches.
`BuildIdByTitle` first maps every title to its id across the id-bearing files, so the title-only files resolve to the *same* id as their id-bearing counterpart.
This is why an id-less `seen_episode_source.csv` episode still attaches to the followed show it belongs to, even after that show's stored title was enrichment-renamed.
`UpsertIndex<TModel>` matches an incoming item by `TvTimeId` first.
A title fallback fires only for a pre-existing record that has **no** `TvTimeId` yet (created by an import predating this feature), which is then adopted and back-filled exactly once (`BackfillTvTimeIdAsync`) rather than duplicated.
A record already carrying a *different* id is left alone, so two genuinely different items sharing a title are never collapsed.
On a match the record is **left untouched** - not merely honoring the "if it already exists, do nothing" rule.
This is because a re-import must never clobber edits the user made *in the app* after the initial import (rating, notes, favorite, a corrected title/year).
Re-applying the export's values on every re-import would silently erase those.
So don't reintroduce an update-on-existing path here.
Only genuinely new items are created, and the result counts `*Created`/`*Skipped` (deduped by reference identity so a show touched in both the followed-shows and episodes phases counts once).
Covered by `TvTimeImportServiceIdempotencyTest` (unit, in-memory repos, re-imports after mutating the stored titles to prove no duplication) and the re-import half of `TvTimeImportResourceTest` (integration).
Note this fixes *future* imports; pre-existing duplicates from earlier buggy runs need a one-off cleanup (a `scripts/*.js` dedupe in the same run-once style as `migrate-poster-url-to-image-url.js`), not yet written.

When a `SeenEpisodeRecord`-shaped property is only present in *some* of the three source files' headers (like `TvShowId`, absent from `seen_episode_source.csv`), it needs a special attribute.
It needs `[Optional]` from `CsvHelper.Configuration.Attributes` in addition to not being C#'s `required`.
CsvHelper's header validation throws on a missing column for any `[Name]`-decorated property regardless of C# nullability unless that attribute is present.
This only surfaces at runtime against a real file missing the column, not at compile time - a unit test with a realistic fixture (matching `seen_episode_source.csv`'s actual header) is what caught it.

Movies were originally believed to have no watch date anywhere in the export ("import movies without a watch date" was the confirmed scope decision).
That turned out to be wrong the same way the episode-history gaps were: `tracking-prod-records.csv`'s generic event log carries `entity_type == "movie"` rows too.
These have `type` "watch" (an individually dated watch event - `Movie.FirstSeenAt`), "towatch" (`Movie.WantToWatch`, only applied when there's no watched event, so a since-watched movie doesn't stay flagged as still-to-watch).
They also have "follow" (existence only, same role as `followed_tv_show.csv` for shows).
`MovieTrackingEventsCsvParser` reads these; `tracking-prod-records-v2.csv` (the newer-generation log) carries no movie data at all - confirmed against a real export, not assumed.
If a future TV Time field looks suspiciously absent, re-check the real export before documenting it as a limitation - this is the second time an "unrecoverable" gap turned out to just be unparsed.

The import runs as a background job rather than a single request/response, so the UI can show real progress.
`POST /api/import/tv-time` buffers the upload, kicks off the work via `IServiceScopeFactory.CreateScope()` (the request's own DI scope is gone by the time the background work runs), and returns a job id immediately.
`GET /api/import/tv-time/{jobId}` reports the current `ImportStage`.
`ImportJobStore` is an in-memory singleton keyed by job id and checks the caller's owner id on every read, so a job is only ever visible to the user who started it.
Follow this shape (buffer input, background `Task` via a fresh scope, pollable status keyed by owner) for any other future long-running action.
Don't block a request on multi-second server work just because the current single-endpoint pattern is simpler to write.

Watch Next originally reported only the *last watched* episode per in-progress show, deliberately never guessing a "next" one, because Keeptrack had no episode-guide data to confirm a further episode actually existed.
That constraint is gone now that `TvShowReferenceModel.Episodes` carries a real TMDB episode list.
`WatchNextService.ComputeInProgressShows` now takes a third parameter, `referencesByShowId`.
It only reports a show if (a) its `Status` is `TvShowStatus.Current` (not merely "not Finished/Stopped" as before) and (b) its linked reference's episode list has an entry after the last one watched.
That entry is compared by `(SeasonNumber, EpisodeNumber)`, not by title or air-date order, and its `AirDate` must have already passed (or be unset).
A show with no `ReferenceId`, or no matching reference document, is excluded rather than guessed at - the same "don't guess when you don't have the info" principle as before, just enforced by data instead of by omission.
`WatchNextController` only fetches the (small, bounded) reference document for shows that are `Current` and linked, since those are the only ones that can possibly appear in the result.
The DTO now also reports the confirmed next episode's season/episode/title (`InProgressShowDto.Next*`).
This was withheld before purely for lack of data, not by design preference, so surfacing it once the data is trustworthy is not a reintroduction of the old "+1" heuristic that shipped a confirmed-wrong result.
That heuristic guessed without confirming an episode existed; this checks a real episode-guide.

`WatchNextService.FilterMoviesToWatch` excludes a movie from the "movies to watch" list once it's marked seen (`FirstSeenAt` set), even though it's still flagged `WantToWatch`.
Toggling that flag on a movie's own detail page doesn't clear it on watch (unlike the TV Time import's "towatch" event handling, which never flags an already-watched movie in the first place).
So the exclusion has to happen at read time here instead of relying on the flag never going stale.

`TvShowDetail.razor`'s episode checklist filters `_reference.Episodes` to `AirDate is null || AirDate <= today` before grouping into seasons.
This is the same air-date filter `WatchNextService` already applies for its "next episode" calc.
An episode TMDB lists with a future air date (a confirmed-but-unaired next season, e.g. a renewal announced months ahead) hasn't happened yet from the viewer's perspective - it shouldn't appear as a checkbox to mark watched.
An entirely future season simply doesn't appear in the season picker at all once every one of its episodes is filtered out.

### Keeping reference data fresh: periodic + on-demand TMDB sync

TMDB's own data (episode air dates as seasons progress, genres, posters, cast) drifts out of date after the initial resolution - a show resolved months ago needs re-checking, not just a one-time fetch.
`ReferenceSyncBackgroundService` (`WebApi/ReferenceData/`) is a plain in-process `BackgroundService` running a `PeriodicTimer` (24h interval, does an initial pass immediately on startup too).
It's deliberately **not** a Kubernetes CronJob or separate worker process.
A second scheduled workload is real operational overhead (another manifest, another thing that can silently stop running) for a job that's cheap enough to run inside the existing API process.
`ReferenceSyncService.SyncStaleReferencesAsync(staleAfter, ...)` is shared by both the periodic loop and the admin's on-demand trigger, so there's exactly one sync algorithm.
It skips any reference document whose `LastEnrichedAt` is more recent than `staleAfter` (3 days for the periodic pass; `TimeSpan.Zero` for the admin's forced "sync now", which therefore re-checks everything regardless of recency).
It never lets one failing document (a TMDB id that's since been removed, a transient network error) abort the rest of the run - each is caught and logged individually.

`ReferenceEnrichmentService.RefreshTvShowReferenceAsync`/`RefreshMovieReferenceAsync` do the actual per-document work, and lead with a cheap pre-check before the expensive full re-fetch.
`ITmdbClient.HasTvShowChangedSinceAsync`/`HasMovieChangedSinceAsync` call TMDB's per-id `/{tv,movie}/{id}/changes?start_date=...` endpoint (one call, no season fan-out) to ask "has anything changed since this was last enriched".
This is the "if TMDB provides the last updated date... check with `last_enriched_at`" idea, implemented via TMDB's changes endpoint since TMDB doesn't expose a plain last-modified field on the show/movie details response itself.
If nothing changed, only `LastEnrichedAt` is bumped (so the next periodic pass doesn't re-check an already-current document) and the costly `GetTvShowDetailsAsync` + per-season `GetTvShowCastAsync` calls are skipped entirely.
A reference with no `LastEnrichedAt` yet always does the full fetch (nothing to compare against, and the changes-check would be meaningless anyway).

An admin can force an immediate full re-check via `POST /api/reference-data/sync-now` (`ReferenceDataAdminController`, admin-only) instead of waiting for the next scheduled pass.
The same "Reference data" admin page that already has export/import gets a "Sync now" button reporting checked/updated counts for both collections.

**Gotcha:** the periodic background service is registered unconditionally in `Program.cs`, but only actually does work when `Features:IsReferenceSyncEnabled` (`AppConfiguration.IsReferenceSyncEnabled`, default `true`) is true.
This is checked fresh on every tick, not once at startup.
The integration test host (`KestrelWebAppFactory`) overrides this to `false` via `ConfigureAppConfiguration` (an in-memory source added last, so it wins over `appsettings.json`).
`UseSetting` was tried first and silently didn't work for a top-level-statement minimal-hosting `Program.cs` like this one - it's loaded too early relative to the rest of configuration and gets overridden back by `appsettings.json`.
Without this, every integration test run spun up its own in-process Kestrel host (one per `IClassFixture<KestrelWebAppFactory<Program>>` test class).
Each one immediately fired real TMDB HTTP calls against whatever reference data the shared test MongoDB happened to hold - noisy and non-deterministic, not a real regression to chase.
Any integration test using a bare `WebApplicationFactory<Program>` instead of `KestrelWebAppFactory<Program>` bypasses this override (this already bit `AuxiliaryResourceTest` once).
Use `KestrelWebAppFactory<Program>` for any new integration test fixture, even one that doesn't need real Kestrel networking, specifically so it inherits this override for free instead of re-solving it.

### Reference data now covers five domains (Book, VideoGame, Album)

The TMDB-backed pattern above (shared `*_reference` collection, admin unresolved queue, user-triggered "check for reference match", periodic + on-demand sync, export/import) is no longer TV-show/movie-only.
`Book`/`VideoGame`/`Album` (the last renamed from `MusicAlbum` for consistency with `Episode`/`CarHistory`-style short names) each get their own external source and reference collection:

- **Books** → Open Library (`IBookReferenceClient`/`OpenLibraryClient`, `WebApi/ReferenceData/`), no API key, `book_reference` collection with an extra `AuthorReferenceId` field.
- **Video Games** → RAWG (`IRawgClient`/`RawgClient`), a single API key appended as a query param (same convention as TMDB's `api_key`), `videogame_reference` with an extra `Platforms` list.
  `VideoGameModel.Platform`/`State` are deliberately never overwritten by a reference link - they describe this tenant's own copy/progress, not the canonical release.
  This is unlike `Title`/`Year`, which do get set on link the same way Movie/TvShow already do.
- **Albums** → Discogs (`IDiscogsClient`/`DiscogsClient`), a personal access token appended as a query param plus a required descriptive `User-Agent` header (Discogs API policy), `album_reference` with an extra `ArtistReferenceId` field.
  Discogs search results title a release as `"Artist - Album Title"` in one string; `DiscogsClient` splits on the first `" - "` to populate `Artist`/`Title` separately.

**Divergence from TMDB:** none of these three APIs expose a TMDB-style per-id `/changes` endpoint, so `Refresh<X>ReferenceAsync` for these three domains has no cheap "has this changed" pre-check.
It always does a full re-fetch once a document is past its staleness cutoff (the cutoff check itself, in `ReferenceSyncService`, is unchanged).
`ReferenceSyncResultDto`'s `Books/VideoGames/AlbumsUpdated` counts are therefore always equal to their matching `*Checked` counts.

**Author/artist matter for search precision, not just display.** A common book/album title alone (e.g. "Killing Floor") returns many unrelated candidates from Open Library/Discogs.
`IBookReferenceClient.SearchBooksAsync`/`IDiscogsClient.SearchAlbumsAsync` both take an optional `author`/`artist` parameter (the provider's own query field for it) precisely to narrow this.
This is threaded through `TryAutoResolveBookAsync`/`TryAutoResolveAlbumAsync` (captured from `BookModel.Author`/`AlbumModel.Artist` in `BookController`/`AlbumController.OnCreatedAsync`) and through the admin's manual search.
The admin's manual search is `ReferenceDataAdminController.Search`'s `creator` query param, surfaced as a free-text box in `ReferenceDataAdminPage.razor`.
It's also `InlineReferenceLinker`'s `Creator` parameter, populated from the tenant's own Author/Artist field on `BookDetail.razor`/`AlbumDetail.razor`.
`ReferenceSearchResultDto.Creator` (book author or album artist; null for TV/movie/game) surfaces this on every search candidate the admin sees.
Without it, an admin looking at otherwise-identical title+year+cover candidates has no way to tell them apart.

**Gotcha:** `OpenLibraryClient.SearchBooksAsync` deliberately never sends `year` as a server-side query filter (unlike TMDB/RAWG/Discogs, which do).
Open Library's `first_publish_year` is a book's ORIGINAL publication year, not whatever edition/printing year a tenant happened to record.
Searching "Killing Floor" (Lee Child, first published 1997) with `first_publish_year=2016` (a tenant's 2016 reprint) returns zero relevant results.
This is because Open Library filters the *work* by that exact year server-side and no edition of that work was first published in 2016.
`year` is still returned per candidate for display/tie-breaking, just never used to narrow the query itself.
This was confirmed against the real API (searching `title=Killing+Floor&first_publish_year=2016` returns an unrelated 2016 book; dropping the year filter and adding `author=Lee+Child` finds the real one).
This is a book-specific problem (one canonical release date doesn't generalize to "the book was first published once, but every reader owns some edition").
RAWG/Discogs keep their year filters since no equivalent bug has been found for games/albums.

Book authors and album artists are deduplicated the same way TV/movie cast is: `PersonReferenceModel`/`person_reference` was kept as-is (no rename) and reused, rather than adding two more near-duplicate lookup tables.
"Person" already meant "a named individual or group identified by an external provider id," not "actor" specifically.
So extending it to a book's author (Open Library author id) or an album's artist (Discogs artist id, which can be a group/band) needed no rename, just reuse.
`BookReferenceModel.AuthorReferenceId`/`AlbumReferenceModel.ArtistReferenceId` point at a `PersonReferenceModel` document instead of embedding a plain name string.
`ReferenceEnrichmentService.ResolvePersonReferenceIdAsync` (shared helper in the core partial-class file) is the single dedup-by-external-id path used by cast resolution (`ResolveCastAsync`, refactored to call it per member) and by `ResolveBookAsync`/`ResolveAlbumAsync`.
`BookReferenceDto.AuthorName`/`AlbumReferenceDto.ArtistName` are hydrated by `ReferenceDataController` joining `person_reference` by id (same `[MapperIgnoreTarget]` + manual join pattern as `Cast`).
The model only carries the id, never a denormalized name, so there's nothing to keep in sync.
When linking (`TryLinkExistingBookReferenceAsync`/`TryLinkExistingAlbumReferenceAsync`), the tenant's own plain-string `BookModel.Author`/`AlbumModel.Artist` is still populated.
This works by resolving the reference's `*ReferenceId` to a name at link time (`ResolvePersonNameAsync`).
The tenant-facing field stays a free-text string editable like `Title`, only the shared reference document uses the dedup'd id.

`ReferenceEnrichmentService` is a single `partial class` split across `.TvShowsAndMovies.cs`/`.Books.cs`/`.VideoGames.cs`/`.Albums.cs` files (one class, same constructor, same five-method-per-domain template: `TryLinkExisting<X>ReferenceAsync`/`TryAutoResolve<X>Async`/`Resolve<X>Async`/`Refresh<X>ReferenceAsync`).
Splitting by file rather than by class keeps the shared helpers (`MergeMatchedAliases`, `TitleNormalizer.Normalize`) in one place without one file growing to cover six domains' worth of logic.
`ReferenceMatchModel`/`MatchedAliases` needed no changes at all to support the new domains - it was already generic, not TMDB-specific, per its original naming decision.

`PosterUrl` was renamed to `ImageUrl` on `TvShowReferenceModel`/`MovieReferenceModel` (and their entities/DTOs/Razor bindings) as part of this.
"Poster" only made sense for movies/TV, and the field is now shared across all five reference types.
Similarly, the admin search/link DTOs' `TmdbId` field was renamed to `ExternalId` (`ReferenceSearchResultDto`, `LinkReferenceRequestDto`).
This is because `ReferenceDataAdminController`'s `Search`/`Link`/`GetUnresolved` endpoints now switch over a 5-way `ReferenceItemType` enum instead of a TV-show/movie ternary.
Hardcoding a TMDB-specific name in a request DTO shared by Open Library/RAWG/Discogs would have been misleading.

`Book`/`VideoGame`/`Album` detail pages (`BookDetail.razor`, `VideoGameDetail.razor`, `AlbumDetail.razor`) follow `MovieDetail.razor`'s exact shape (own route, own load/save methods, no `InventoryPageBase` inheritance).
Cover art, synopsis and genres render when linked, plus the same refresh-reference icon button and admin `InlineReferenceLinker`.
None of the three have a cast/credits concept, so there's no `CastGrid` equivalent for them.

**Gotcha:** `OpenLibraryClient.GetBookDetailsAsync` fetches a work's year from `first_publish_date` on `/works/{id}.json`, but that field is routinely absent from the work document itself.
This was confirmed against the real API for a book as well-known as Lee Child's "Killing Floor" (`/works/OL24477958W.json` has no `first_publish_date` at all), while the search index's computed `first_publish_year` for the same work is reliable.
`GetBookDetailsAsync` falls back to `FindPublishYearViaSearchAsync` (a single-document `q=key:{workKey}` search re-query) whenever the work-level parse comes back null.
This is rather than silently leaving `BookReferenceModel.Year`/the tenant's own `BookModel.Year` unset after a link.

**No reliable "series" field exists in Open Library.** Checked directly against the real API (work JSON, edition JSON, and a `fields=*` search query for "Killing Floor") - none expose a `series` field.
The closest available signal is the search index's `person`/`subject_people` facet (a recurring fictional character, e.g. `"person": ["Jack Reacher"]` for "Killing Floor"), but that's a character-name facet, not a series title.
It doesn't generalize (many series aren't named after - or don't have - a recurring eponymous character, and a standalone book can still feature a named character).
It's not wired up to `BookModel.Series`/`BookReferenceModel` for that reason - auto-filling `Series` from it would be right by coincidence for character-titled franchises and wrong or absent otherwise.

`Album`/`Book` gained `IsFavorite` (`AlbumModel`/`Album`/`AlbumDto`, `BookModel`/`Book`/`BookDto`), same shape as `Movie`/`TvShow`'s existing flag: a partial Mongo index (`album_favorite`/`book_favorite`, `scripts/mongodb-create-index.js`), a `Favorites` filter button in each list page's `Filters` slot, and a toggle button on `AlbumDetail.razor`/`BookDetail.razor`'s page header (same `kt-toggle-btn`/`active` pattern as `MovieDetail.razor`).

`VideoGameModel.State` stays a plain free-text string (not an enum like `TvShowModel.State`) deliberately.
Real tenant data already has values like `"To resume"`/`"On-hold"` that aren't valid C# enum member names, and MongoDB's `EnumRepresentationConvention(BsonType.String)` deserializes by matching the enum member name exactly.
So converting would require a data migration with real breakage risk for existing documents.
Filtering by state (`VideoGameRepository.GetFilter` already supported exact-match filtering by `input.State`) is instead exposed as list-page filter buttons (`VideoGames.razor`'s `Filters` slot, same visual pattern as `TvShows.razor`'s `TvShowStatus` filter buttons) over the existing string values.
The Add/Edit forms' State `<select>` was replaced with a button group (`VideoGames.VideoGameStates`, the shared array both the filter and the form buttons iterate over) for the same reason TvShow's own state buttons exist - clicking a value is faster than a dropdown for a small fixed set.
`FinishedAt` is a plain, always-visible date field on `VideoGameDetail.razor`'s card (not a corner-flag toggle like `MovieDetail.razor`'s "Mark as watched"/`BookDetail.razor`'s "Mark as read").
It was previously only editable once already set elsewhere, with no way to set it from scratch on the detail page.
Unlike Movie/Book, "finished" already has its own explicit `State` value ("Completed") to toggle, so `FinishedAt` doesn't need a second boolean-flag affordance layered on top.

**`VideoGameDetail.razor`'s own State editor follows `TvShowDetail.razor`'s per-item State pattern exactly, not the list page's filter-button pattern.** These look superficially similar (both are button rows) but behave differently, and the two were conflated once already.
The per-item editor buttons live in their own row directly below the page header (not inside the `kt-form-card` next to Year/Rating).
Clicking the already-active value clears it back to unset (`SetStateAsync`: `_game.State = _game.State == state ? "" : state`, mirroring `TvShowDetail.razor`'s own `SetStateAsync`).
The list page's filter buttons are a different control with different semantics (an explicit "All" option to clear, since a filter and a per-item value aren't the same kind of state).

**`TvShowModel.Status` was renamed to `TvShowModel.State`** for naming parity with `VideoGameModel.State` (`TvShowDto.State`, `TvShow.State` entity property, `TvShowRepository.GetFilter`'s `input.State`, `TvShows.razor`'s `_stateFilter`/`SetStateFilterAsync`/`ExtraQuery["State"]`, `TvShowDetail.razor`'s `SetStateAsync` all renamed to match). The enum type itself keeps its `TvShowStatus` name - only the property that holds it moved to `State`, since `VideoGameModel.State` has no equivalent enum to rename against. Unlike the `PosterUrl`→`ImageUrl` rename below, this one needed **no** data migration: `TvShow`'s entity property kept an explicit `[BsonElement("status")]` pointing at the unchanged storage name, so existing documents (confirmed directly against the real dev database - `status: 'Finished'` reads back correctly through the renamed `State` property) deserialize with no script required. `TvTimeImportService`/`ShowStatusCsvParser`'s `ShowStatusRecord.Status` is a same-named but *entirely unrelated* field - TV Time's own CSV column for favorite/for_later, mapped to `IsFavorite`/`WantToWatch`, never to this enum - so the import pipeline needed no changes at all for this rename; verified by tracing every consumer before renaming, not just running the test suite. `WatchNextService`/`WatchNextController`'s `Status == TvShowStatus.Current` checks were updated to `State == TvShowStatus.Current` and covered by `WatchNextServiceTest`, which still passes.

**Gotcha:** an optional narrowing parameter on an external search must never be allowed to silently zero out results that a broader search would find - this bit both the Open Library year filter (see above) and, separately, `IDiscogsClient.SearchAlbumsAsync`'s `artist` parameter: a tenant's own `AlbumModel.Artist` text passed straight through as Discogs' `artist=` query field can fail to match Discogs' own exact indexing (a disambiguation suffix like `"Artist (2)"`, different capitalization/formatting), returning zero candidates even though the title alone finds the album - confirmed with a real title ("Born Pink") that returned nothing via `AlbumDetail.razor`'s `InlineReferenceLinker` (which always passes the tracked album's own `Artist`) but succeeded via the admin page (whose first search per selected item always passes no creator). Both `DiscogsClient.SearchAlbumsAsync` and `OpenLibraryClient.SearchBooksAsync` now retry once without the narrowing author/artist parameter whenever the constrained search comes back empty, rather than reporting a false "not found."

**Gotcha:** `OpenLibraryClient` searched via `search.json?title=...` (a field-scoped exact match against the work's own canonical title), which misses regional title variants entirely - confirmed against the real API that "Harry Potter and the Sorcerer's Stone" (the US title) only matches a handful of near-empty, 1-edition work stubs this way, because Open Library's actual canonical work for this book is titled "Harry Potter and the Philosopher's Stone" (the UK title) and carries 398 editions. Switched to `search.json?q=...` (a general relevance-ranked query across title, alternate titles, etc.), which correctly surfaces the well-populated canonical work first in this case while still returning the same top result as before for titles that don't have this regional-variant problem (e.g. "The Return of the King"). This also explains why some resolved covers can look like a plain, uninteresting library rebinding rather than an illustrated dust jacket even once the *correct* work is matched (confirmed for "The Return of the King", `OL27455W`) - Open Library's own `covers` array for a work is whatever has been scanned/contributed, not curated by "which looks best," and the first entry there is already identical to the search index's own `cover_i` in the cases checked; there's no metadata signal (short of actual image content analysis, out of scope here) to pick a nicer-looking alternative from the same array.

**Gotcha:** when `PosterUrl` was renamed to `ImageUrl` on `TvShowReferenceModel`/`MovieReferenceModel`, existing `tvshow_reference`/`movie_reference` documents created before the rename kept their data under the old `poster_url` BSON field - the new entity class only ever reads `image_url`, so every pre-existing reference document silently lost its cover image (confirmed against a real dev database: 72/87 TV show references and 343/353 movie references still had the old field name). Fixed with a one-off migration, `scripts/migrate-poster-url-to-image-url.js` (idempotent `$rename`, safe to re-run) - run it once against any environment with reference data older than the rename. This is the same class of risk as the earlier `music-album` → `album` collection rename (see "Reference data now covers five domains" above): a data-shape rename in code needs an explicit, documented migration step for whatever already exists in Mongo, not just updated `[BsonElement]` attributes.

`ReferenceMatchModel.Creator` (nullable `string`) extends the `MatchedAliases` match key beyond just (title, year) - a title+year match alone risks silently linking a tenant's book/album to a *different* tenant's unrelated one that happens to share a common title and year (a generic name re-published/re-released the same year is common; TV/movie titles almost never collide this hard, which is why they don't need this). `IBookReferenceRepository`/`IAlbumReferenceRepository`'s `FindByTitleYearAsync`/`FindByTitleAsync` now take a required `author`/`artist` parameter and add a `Creator` equality condition to the same `ElemMatch` filter (both title and creator normalized via `TitleNormalizer.Normalize`) - `Creator` is always derived from the **canonical** resolved `details.Author`/`details.Artist` (the external API's own response), never from whatever text the tenant/admin originally typed, since that let the design avoid adding a new parameter to `ResolveBookAsync`/`ResolveAlbumAsync`, `LinkReferenceRequestDto`, or the admin linking UI. TvShow/Movie/VideoGame's `MergeMatchedAliases` calls all pass `null` for `Creator` (no creator dimension in those domains' match key) - the shared helper's third tuple element is `null` for them, not omitted, since `ReferenceMatchModel` stays one generic shape across every domain rather than growing a Book/Album-only subtype. `BookReferenceRepository`/`AlbumReferenceRepository.UpsertAsync`'s defensive "always include the canonical title/year alias" safety net can't set `Creator` (the model only carries `AuthorReferenceId`/`ArtistReferenceId`, a dedup'd link, not denormalized text) - that alias is simply unreachable via the creator-required find methods, which is harmless (the normal Resolve/Refresh path always adds a proper creator-bearing alias first) rather than a false-positive risk; a real-MongoDB integration test (`BookReferenceRepositoryTest`/`AlbumReferenceRepositoryTest`) asserts on the stored alias directly for this specific case rather than through the creator-required lookup, since that lookup can no longer find it by design.

**Gotcha (historical - structurally fixed by the AutoMapper -> Mapperly migration):** `MergeMatchedAliases`' dedup check compares a freshly-computed `Creator` against an existing alias's `Creator` (`m.Creator == normalizedCreator`), which used to silently duplicate aliases on every re-resolve/re-refresh for TV show/movie/video game (the three domains that always pass `null` for `Creator`, having no creator dimension). The reason: `AllowNullDestinationValues = false` (a profile-wide AutoMapper default, since removed along with AutoMapper itself) substituted `""` for a null *string* member during model → entity mapping - so a freshly-built alias with `Creator = null` got persisted as `Creator = ""`, and on the *next* resolve/refresh the freshly computed `normalizedCreator` (still literally `null`) never equalled that already-persisted `""`, so the dedup check saw no existing match and appended an exact duplicate `{title, year, creator: ""}` entry. Confirmed against a real video game reference (RAWG's "God of War", resolved/refreshed more than once) that had accumulated a literal duplicate alias this way.

The fix belonged at the mapping/entity layer, not as a comparison workaround in `MergeMatchedAliases` (an `(m.Creator ?? "") == (normalizedCreator ?? "")` patch was tried first and reverted) - at the time, `DataStorageMappingProfile`'s `ReferenceMatchModel` → `ReferenceMatch` map opted `Creator` out of the profile-wide default with `.ForMember(x => x.Creator, opt => opt.AllowNull())`, so a null `Creator` reached Mongo as an actual null again, and `MergeMatchedAliases` stayed a plain, honest `m.Creator == normalizedCreator`. That per-member opt-out is gone now, not just moved: Mapperly (the current mapper) preserves nulls by default, so every storage mapper's `Creator` mapping is a real null with no configuration needed at all - this entire class of bug is structurally impossible today, not merely patched. From there, the *already-registered*, codebase-wide `IgnoreIfNullConvention(true)` (`InfrastructureServiceCollectionExtensions.AddMongoDbInfrastructure`) does the rest for free - it omits any null property from the stored document, which is why `Year` (also nullable on `ReferenceMatch`) was never affected by this bug in the first place and needed no equivalent per-property `[BsonIgnoreIfNull]` fix; that attribute doesn't appear anywhere in this codebase, and shouldn't - "is this field omitted when unset" is a driver-convention-level answer here, not a per-entity one. Was covered by `RefreshVideoGameReferenceAsync_DoesNotDuplicateAnAliasAlreadyPersistedWithANullCreator` (unit, mocked) and `TvShowReferenceRepositoryTest.UpsertAsync_PersistsANullCreator_AsAnActualBsonNullNotAnEmptyString` (integration, real MongoDB - the only way to actually catch a serialization-level regression like this one); both still pass under Mapperly as a regression guard, even though the bug they were written for can no longer occur. A scan of the real dev database found only the one "God of War" document actually duplicated, cleaned up with the idempotent `scripts/dedupe-matched-aliases.js` (same "run once per environment" pattern as `migrate-poster-url-to-image-url.js`).

`BookModel`/`AlbumModel.Genre` (a single free-text field, not a list - it predates the reference-data feature, same as `Author`/`Artist` before `PersonReferenceModel` existed) is now propagated on link the same way `Title`/`Year`/`Author`/`Artist` already are: `TryLinkExistingBookReferenceAsync`/`TryLinkExistingAlbumReferenceAsync` and `ResolveBookAsync`/`ResolveAlbumAsync` join the reference's `Genres` list (`JoinGenres`, a shared helper in `ReferenceEnrichmentService.cs`) into that single field, both on the tenant's own document and via `IBookRepository`/`IAlbumRepository.SetReferenceLinkAsync`'s new `canonicalGenre` parameter (cross-tenant propagation, same incremental-parameter pattern already used for `canonicalAuthor`/`canonicalArtist`) - null (not overwritten) when the reference has no genres, same "don't overwrite with nothing" rule the other propagated fields already follow. `BookDetail.razor`/`AlbumDetail.razor` previously displayed the *reference's* raw `Genres` list directly (a read-only comma-joined paragraph) but never touched the tenant's own `Genre` field at all - that display was replaced with a plain editable `Genre` input (same shape as `Author`/`Series`/`Artist`), matching how `Author`/`Artist` already work: the reference data flows into the one tenant-owned field on link, there's no separate "raw reference value" display once linked.

Books are the one reference domain behind a provider-agnostic interface rather than a provider-named one: `IBookReferenceClient` (`BookSearchResult`/`BookDetails` DTOs, an `IBookReferenceClient.ProviderKey` string) instead of `IOpenLibraryClient`. TV show/movie/video game/album stay hard-wired to TMDB/RAWG/Discogs directly (their DTOs and hardcoded `"tmdb"`/`"rawg"`/`"discogs"` `ExternalIds` keys are provider-named on purpose - swapping any of those would be a bigger redesign, not a config change). Which implementation of `IBookReferenceClient` is registered is a deployment-time choice, `ReferenceData:BookProvider` (`ReferenceData__BookProvider` as an environment variable, `Program.cs` switches on it), defaulting to `OpenLibrary` - the only implementation that ships today. `ReferenceEnrichmentService.Books.cs` never hardcodes a provider name; every `ExternalIds`/person-reference lookup keys off the injected `IBookReferenceClient.ProviderKey` instead, so a second implementation only needs its own class (`OpenLibraryClient`-shaped: base address, optional settings class, `ProviderKey`) plus one new `case` in `Program.cs` - no changes to the enrichment service or admin controller.

### Blazor app

`InventoryPageBase<TDto>` (`BlazorApp/Components/Inventory/InventoryPageBase.cs`) centralizes list/paging/search/inline-edit state and calls into `InventoryApiClientBase<TDto>`, which wraps the typed `HttpClient` calls to the Web API (its `GetAsync` takes an optional extra-query-parameters dictionary, used by features that filter on more than search/page/pageSize). Each concrete page (`Books.razor.cs`, `Movies.razor.cs`, ...) only supplies its `Api` instance and `CloneItem`. A page that needs its own filter beyond search (e.g. `TvShows.razor.cs`'s state filter) overrides the base's `protected virtual ExtraQuery` property instead of reimplementing paging/search - `LoadAsync` is `protected` for exactly this reason, so the page can trigger a reload after changing its own filter state. Authentication uses Firebase (cookie auth in the Blazor app, JWT bearer validated against Firebase in the Web API); `AuthenticationTokenHandler` attaches the bearer token to outgoing API calls.

Pages that aren't a generic CRUD list (`TvShowDetail.razor`, `WatchNext/WatchNextPage.razor`, `Import/ImportPage.razor`) don't extend `InventoryPageBase`/`InventoryList` — they're free to build their own layout on top of the shared `kt-*` CSS classes in `app.css`. Their API clients live next to them in a feature folder rather than in `Inventory/Clients/`.

**Gotcha:** passing a field to a `string`-typed component `[Parameter]` needs the `@` prefix - `Title="_movie.Title"` binds the **literal text** `"_movie.Title"`, not the property's value. Razor only auto-detects that an attribute value must be C# code when the parameter's type couldn't otherwise accept a string literal (e.g. `Year="_movie.Year"` on an `int?` parameter works unprefixed, because a bare identifier can't type-check as one); a `string` parameter can always accept a literal, so Razor takes it at face value instead. This compiles and renders with no error - the bug only shows up in the *data*, not the markup - which is exactly what happened when `InlineReferenceLinker`'s `Title="_movie.Title"` sent the literal string `_movie.Title` to TMDB's search instead of the movie's actual title, returning an unrelated result. Always write `Title="@_movie.Title"` for string parameters bound to a field/property.

### Theme

`app.css` is a light+dark theme driven by `data-bs-theme` on `<html>` (Bootstrap 5.3's native color-mode support), with Keeptrack's own `--kt-*` tokens layered on top for custom components (sidebar, `kt-table-wrap`, `kt-modal`, etc.). `wwwroot/theme.js` sets the initial theme from `localStorage`/`prefers-color-scheme` before first paint (avoiding a flash of the wrong theme) and exposes `ktToggleTheme()`, called directly from a plain button in `NavMenu.razor` — no Blazor/JS interop needed for the toggle itself. Use system-ui fonts only; no decorative/display webfonts.

Icons throughout the app are plain Unicode symbols with no default emoji presentation (`◈`, `✓`, `✕`, `★`, `▶`, `↻`, `⌂`, `⚙`, `♪`, and the Geometric Shapes block generally: `◼ ▭ ▬ ◆`), never a codepoint whose default rendering is a full-color emoji glyph (`⭐`, `👁`, `🔄`, `⏳`, `🏠`, `📚`, `🎬`, ...) - a color emoji reads as an inconsistent, slightly unpolished note among otherwise monochrome UI that follows `--kt-text`/`--kt-accent` like everything else. **Gotcha:** a codepoint isn't safe just because it "looks like" a plain symbol - `⭐` (U+2B50) and `👁` (U+1F441) were originally used as the "Best of"/"Want to watch" icons on the assumption they were plain stars/eyes, but both have `Emoji_Presentation=Yes` by default (Unicode's `emoji-data.txt`) and render as full-color glyphs on every mainstream platform; they were replaced with `★` (U+2605, Black Star, default text presentation) and `▶` (U+25B6, default text presentation) respectively. Before adding a new symbol, check whether its default presentation is text or emoji - don't assume from how it looks in this file. Appending a trailing variation selector (`️`, U+FE0F) forces emoji presentation even on an otherwise-safe codepoint, so never add one; some codepoints (`🌙`, `🚪`, `🔑`, `👤`, `📦`) have no text-presentation form at all and were simply dropped rather than replaced with an approximate glyph, since a semantically-forced match is worse than no icon when the row's label text already carries the meaning. `.kt-icon-spin` (reuses the same `spin` keyframes as `.kt-spinner`) makes a plain glyph rotate in place for a small inline action's "in progress" state, instead of swapping to an hourglass emoji.

Enhanced navigation re-fetches and diffs the whole document on every in-app link click; anything set on `<html>`/`<body>` by client-side JS rather than server-rendered markup (like `data-bs-theme`) gets stripped back out unless it's explicitly re-applied. `wwwroot/Keeptrack.BlazorApp.lib.module.js` is a JS initializer (auto-loaded by Blazor because its name matches the assembly - don't add a manual `<script>` tag for it) that re-applies the theme via `blazor.addEventListener('enhancedload', ...)`. Any future client-side DOM state that isn't part of the Razor render tree needs the same treatment.

Before assuming a rule in `app.css` will style something, check whether that element has its own scoped `{ComponentName}.razor.css` file (Blazor CSS isolation) - a scoped selector always wins the cascade over an equally-specific one in the shared stylesheet, since it's compiled with an extra scope attribute. This is exactly what caused the reconnect-modal (`ReconnectModal.razor.css`) to render with the original scaffolded white/blue colors despite an app.css override that looked like it should have applied; the scoped file itself has to be edited.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C#/Razor, LF line endings, `var` preferred everywhere, braces required, `_camelCase` for private instance fields, `s_camelCase` for private static fields, PascalCase for everything else. Avoid `this.` qualification.
- Primary constructors are the norm for controllers, repositories and API clients (see `BookController`, `BookRepository`, `BookApiClient` above).
- Nullable reference types are enabled across all `src` projects; use `required` for non-nullable properties that have no sensible default (e.g. `BookModel.Title`).
- Public WebApi.Contracts DTOs and WebApi controllers carry XML doc comments (`GenerateDocumentationFile` is enabled) because they feed the generated OpenAPI/Scalar documentation.
- Markdown files: 2-space indent, no trailing-whitespace trimming, max line length 240 (`.markdownlint-cli2.yaml`). In addition, write one sentence per line inside multi-sentence paragraphs: never cut a sentence, keep each sentence as short as possible, and start a new line right after the period that ends it. Single-sentence paragraphs/list items don't need to be split further.

## Tests

- `test/WebApi.UnitTests`: xunit v3 unit tests, e.g. the TV Time import parsers (`Import/Parsers/`, pure stream-in/records-out, no I/O beyond an in-memory stream), and `WatchNextService` (pure next-episode computation). Mapper configuration validation is a compile-time concern now (Mapperly's `RMG012`/`RMG020` diagnostics, escalated to build errors in `.editorconfig`), not a unit test - there's no equivalent of the old `AutoMapperConfigurationTest` to run here anymore.
- `test/WebApi.IntegrationTests`: xunit v3 tests booted against a real Kestrel host (`KestrelWebAppFactory<Program>`) and a real MongoDB instance. `ResourceTestBase` provides typed `GetAsync`/`PostAsync`/`PutAsync`/`DeleteAsync`/`PostFileAsync` helpers and an `Authenticate()` helper that logs in against Firebase to obtain a bearer token. Resource tests (`BookResourceTest`, `MovieResourceTest`, `TvTimeImportResourceTest`) exercise a full create/read/update/delete (or upsert) cycle against the live API and clean up what they create. `TvTimeFixtureZipBuilder` builds a small synthetic TV Time export in memory for the import test — never commit a real personal export as a test fixture.
- Assertions use `AwesomeAssertions` (a `FluentAssertions`-compatible API); test data is generated with `Bogus`.

## CI

GitHub Actions (`.github/workflows/ci.yaml`) runs, on push/PR to `main`: a git/markup lint job, a .NET quality job (build, test with coverage, SonarCloud, FOSSA license/security scan) gated on app changes, and a container image scan for both Dockerfiles. Equivalent pipelines exist for GitLab CI and Azure DevOps.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms. Hold every change to this standard, not just new code.

- No duplicated algorithms or logic. Duplicated data shapes (a `Model`, an `Entity`, and a `Dto` that mirror the same fields) are fine and expected; duplicating the logic that operates on them is not. If two repositories, controllers, or components need the same behavior, it belongs in a shared base class or method, following the existing `DataCrudControllerBase<TDto, TModel>` / `MongoDbRepositoryBase<TModel, TEntity>` / `InventoryPageBase<TDto>` pattern.
- Every non-trivial piece of logic needs a test, especially per-type overrides like `GetFilter`. These are the most duplicated, least-reused pieces of code in the solution, and history has already shown they are where bugs hide (see `docs/code-quality-findings.md`).
- Before proposing a fix, verify the current best-practice for the specific library/framework version in use (e.g. MongoDB driver filter semantics, current ASP.NET Core guidance) rather than relying on older patterns from training data.
- Known findings from past reviews, including which items are confirmed bugs versus intentional by-design behavior, are tracked in `docs/code-quality-findings.md`. Check it before re-reporting something already triaged there, and update it when a listed item is fixed.
