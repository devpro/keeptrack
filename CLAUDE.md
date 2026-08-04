# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Project overview

Keeptrack is source-available (PolyForm Strict 1.0.0, see `LICENSE` - not open source).
It lets users save and review everything they read, watch, listen to or play (books, movies, TV shows, albums, video games, plus car, house and health journals).

Three-tier .NET 10 / C#: `BlazorApp` (Blazor Server UI), `WebApi` (ASP.NET REST API), MongoDB.

## Commands

```bash
dotnet restore && dotnet build

dotnet run --project src/WebApi      # https://localhost:5011/
dotnet run --project src/BlazorApp   # https://localhost:5021/

dotnet test                          # Microsoft.Testing.Platform runner, xunit v3
dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.Services.WatchNextServiceTest.ComputeInProgressShows_*"

docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile

docker run --name mongodb -d -p 27017:27017 mongo:8.2   # required for WebApi + integration tests
```

Integration tests need Firebase test-user credentials and MongoDB settings, as env vars or in a `Local.runsettings` at the repo root (template in `CONTRIBUTING.md`; never commit it).

**Gotcha:** `--settings Local.runsettings` cannot be combined with `--filter-method`/`--filter-class`.
`--settings` switches `dotnet test` to legacy VSTest mode, which rejects the MTP filter flags and silently runs zero tests (exit code 5).
For a filtered subset, load the runsettings env vars into the shell instead:

```powershell
[xml]$rs = Get-Content Local.runsettings
$rs.RunSettings.RunConfiguration.EnvironmentVariables.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | ForEach-Object { Set-Item -Path "env:$($_.Name)" -Value $_.InnerText }
dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "Keeptrack.WebApi.IntegrationTests.Resources.WishlistResourceTest.*"
```

A full unfiltered run can still use `--settings`.

## Architecture

Layered / clean architecture across small single-purpose projects (`src/*`), `Domain` at the center, nothing references "outward":

Project                  | Depends on                                             | Responsibility
-------------------------|--------------------------------------------------------|---------------
`Common.System`          | —                                                      | Cross-cutting primitives: `IHasId`, `IHasIdAndOwnerId`, `PagedRequest`, `PagedResult<T>`, `TitleNormalizer`, `ListSort`.
`Domain`                 | `Common.System`                                        | Business models (`Models/*Model`), repository interfaces (`Repositories/I*Repository`), pure services (`Services/`). No persistence or web concerns.
`Infrastructure.MongoDb` | `Domain`                                               | BSON `Entities/`, `Repositories/`, `Mappers/`.
`WebApi.Contracts`       | `Common.System`                                        | Public REST DTOs (`Dto/`), shared with `BlazorApp` so the client deserializes without duplicate classes.
`WebApi`                 | `Infrastructure.MongoDb`, `Domain`, `WebApi.Contracts` | Controllers, DTO mappers, DI, JWT auth, OpenAPI/Scalar.
`BlazorApp`              | `Common.System`, `WebApi.Contracts`                    | Blazor Server UI over HTTP; never references `Domain`/`Infrastructure.MongoDb`.

### Data model conventions

Every user-owned entity implements `IHasIdAndOwnerId` at all three layers, one class each.
Mapping is compile-time via [Riok.Mapperly](https://github.com/riok/mapperly): one `[Mapper]` partial per pair in `Infrastructure.MongoDb/Mappers/` (`IStorageMapper<TModel, TEntity>`) and `WebApi/Mappers/` (`IDtoMapper<TDto, TModel>`).

- Unmapped members are **build errors** (`RMG012`/`RMG020` escalated in `.editorconfig`).
  Add an explicit `[MapperIgnoreSource]`/`[MapperIgnoreTarget]` for a member a direction genuinely doesn't need; never leave one unmapped.
- `OwnerId` uses `[MapValue(nameof(Model.OwnerId), "")]` on DTO -> model (a plain ignore won't compile - it's `required`).
  The placeholder is overwritten server-side from the caller's claims in `DataCrudControllerBase`, never trusted from client input.
- Read-only feature controllers (`WatchNextController`, `WishlistController`, Car/House metrics, `ReferenceDataController`) use a small one-directional Model -> Dto mapper class injected by its concrete type.
- An enum used in a Domain model needs a **separate** copy in `WebApi.Contracts` (Contracts doesn't depend on Domain).
  Keep member names identical; DTO mappers set `EnumMappingStrategy.ByName`, so drift becomes a build diagnostic.
  Mongo entities reuse the Domain enum directly.
- A nullable DTO member mapping to a `required` model member needs an explicit fallback: `CommonDtoMappings.ToRequiredString` (attached via `[UseStaticMapper]`).
  `CarDto.EnergyType` (nullable, and a different enum type) has its own hand-written `[UserMapping]` wrapping the generated `ByName` conversion.

### Adding a new trackable item type

Follow `Book`/`Movie`/`Album`/`TvShow`/`VideoGame`/`Car` as the template.
A new type touches every layer:

1. `Domain/Models/<X>Model.cs` + `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` (explicit `[BsonElement("snake_case")]`) + `Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs` (XML doc comments feed the OpenAPI spec).
4. `WebApi/Controllers/<X>Controller.cs`: a one-line class extending `DataCrudControllerBase<TDto, TModel>`.
   CRUD logic is never duplicated per controller.
5. Register the repository + storage mapper in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`; register the DTO mapper in `Program.cs`.
6. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` (extends `InventoryApiClientBase<TDto>`) plus `Pages/<X>.razor`/`.razor.cs` (extends `InventoryPageBase<TDto>`, overrides `ListRoute`).
   The Add form carries only identity fields (title/name, creator, year - bare placeholder inputs); everything else is edited on the detail page, which starts with a `<Breadcrumb/>`.
   List rows are uniform media rows rendered by `InventoryList` (cover thumb, title, per-type `MetaTemplate`, delete icon); the whole row opens the detail page and there is deliberately no per-row edit modal.
7. Declare indexes in `scripts/mongodb-create-index.js` (natural-key uniqueness, query shapes, partial indexes for sparse flags).
8. If reference-linked: the DTO implements `IReferenceLinkedDto` (server-hydrated `ImageUrl`, ignored both ways in the mapper), the reference repository gets a batched `FindByIdsAsync`, and the controller overrides `OnListMappedAsync` to
   hydrate covers via `ReferenceImageHydrator` - one batched lookup per page, never one per item.

**Gotcha:** a DTO used by `InventoryPageBase<TDto>` can never have a `required` member - that base is constrained `where TDto : IHasId, new()`, and any `required` member breaks `new()` (`CS9040`).
That's why `BookDto.Title`, `CarDto.Name` etc. are nullable while their models are `required`: a hard language limitation, not an inconsistency to "fix".
DTOs with no `InventoryPageBase` usage (`CarHistoryDto`) mirror `required` in full.

### Ownership: owned versions, never a stored flag

An item is "owned" exactly when it has at least one owned copy; the old stored `is_owned` boolean was removed as a duplicate flag that could drift.

- `Movie`/`TvShow`/`Book`/`Album` embed `List<OwnedVersionModel>` (`owned_versions`): `CopyType` (`Physical` first so it's the default, or `Digital`), optional `Price` (`decimal`/Decimal128, currency-agnostic), `AcquiredAt` (`DateOnly` via
  `CommonStorageMappings`), `Vendor`, and free-text `Reference` (edition/order number - unrelated to `ReferenceId`).
- Video games have **no** `OwnedVersions`: their per-platform entries already carry a `CopyType` and *are* the copies, so a game is owned when `Platforms` is non-empty.
- `IsOwned` survives only as a filter-only query parameter; repositories translate it to `SizeGt(OwnedVersions/Platforms, 0)` and the `*_owned` partial indexes match that predicate.
  Storage mappers ignore it both ways - don't map it to an entity field again.
- Detail pages share `OwnedVersionsEditor`/`OwnedVersionFields` (`Components/Inventory/Shared/`); list rows derive the "Owned" badge from `OwnedVersions.Count > 0` (video games show platform badges instead).
  A NEW copy is a draft card with Save/Cancel (nothing persists until Save); an already-saved copy auto-saves on change like every other detail field.
  Removing a saved copy uses `Components/Shared/TrashIcon.razor` + `ConfirmModal`, skipped when the copy is entirely empty.
- `VideoGamePlatformModel.ProductName` is the store's own product/edition text for that copy, distinct from `Title`.
  It renders through `OwnedVersionFields`' `ExtraFields` slot rather than being added to `IOwnedCopyDto`, since no other type has the concept. The component's columns are unnumbered `col-md` (equal-width auto layout) so an extra column
  re-shares width instead of wrapping.
- Migration for existing data: `scripts/migrate-is-owned-to-owned-versions.js`, then re-run `scripts/mongodb-create-index.js`.

### Bulk store/retailer transaction imports

Three importers of the same shape, all with the controller in `Controllers/` and pure parsing/computation in `Domain/Services/`:

- `AmazonImportController`/`AmazonOrderPreviewService` - order-history CSV; keeps only what's Amazon-specific (`FormatOrderReference` = ASIN + order id, `BuildAmazonProvenanceNotes`).
- `GenericVideoGameImportController`/`GenericVideoGameImportService` - video-game-only transaction CSV (PSN's GDPR export today; `Vendor` is a per-row column, so any store with that shape works).
- `GenericImportController`/`GenericImportService` (`POST /api/import/generic`, `MemberOnly`) - **the store-agnostic default;
  extend this rather than adding another store-specific importer.** Reads a canonical, case-insensitive column set (all optional except `Title`) the user reshapes any export into.
  A `Type` column sets each row's `ImportMediaType` directly (`ParseMediaType` tolerates "TV Show", "Video Game", "Film", "Jeu"...); a blank/unrecognized value falls back to the per-row picker rather than guessing.
  Aliases cover real headers (`Product Name`→Title, `ASIN`/`SKU`→`ProductId`, `Total Amount`→Price, `Product Condition`→Condition).
  `Vendor` (store name) and `Website` are **separate** columns: `Vendor`→the copy's Vendor, `Website`→the copy's `Reference`.
  `Condition` is preserved on the copy's `ProductName` field (deliberate difference from Amazon, owner's request).

Shared engine, never duplicated: `Domain/Services/OwnedItemImportMergeService.cs` (`ComputeCommitPlan`/`FindImportedReferences`, matching by normalized title via `TitleNormalizer`, merging within the same commit batch), returning
`Domain/Models/ImportCommitPlan.cs`.
Per-type create/merge orchestration lives once in `Domain/Services/OwnedItemImportCommitCoordinator.cs`: both multi-type controllers pass a flat `List<OwnedItemImportInput>` and read back per-type `OwnedItemImportCommitCounts`.

`ImportMediaType` exists as two identically-named enums (`Domain.Models` and `WebApi.Contracts.Dto`, mapped by name); a controller importing both namespaces must alias one, same as `CopyType`.

**Gotcha (confirmed against a real PSN export):** a transaction/order id pair is *not* unique per line the way Amazon's ASIN is -
one transaction can bundle several products (three "Far Cry 4" DLC packs, distinguishable only by Product Name).
A reference built from transaction + order id alone made bundled lines collide and be silently skipped as duplicates.
Any import reference/dedup key needs a per-product disambiguator (Product Name here, ASIN for Amazon, order id + product id for generic).
Same fix applied to `GenericVideoGameImportPreviewRow.RowId`.

**`VideoGamesCreated`/`VideoGamesMergedInto` count distinct items, not selected rows - it undercounts rows on purpose.** Rows sharing a normalized title consolidate into one item within a batch.
`ImportCommitPlan<TModel>.OwnedCopiesAdded`/`...CommitResultDto.RowsImported` is the true per-row count (`RowsImported + Skipped` always equals rows submitted) and `SkippedRowTitles` names what was skipped, so the UI can show a reconciling
"X of Y selected rows imported".

### Child entities (1-to-many owned by another entity)

`CarHistory`/`Car`, `Episode`/`TvShow`, `HouseHistory`/`House`, `HealthRecord`/`HealthProfile` are separate top-level collections referencing the parent by id (`car_id`, `tv_show_id`, ...), not embedded arrays.
Deliberate: these grow unbounded per parent, and features query them across *all* of a user's parents at once (Watch Next), which needs a plain indexed query rather than `$unwind`.
Embed only genuinely small, always-together, never-queried-alone data (`TvShowReferenceModel.Episodes` is the counter-example: bounded, always fetched whole, never queried across shows).

- `GetFilter` on a child repository filters the parent id with `Eq`, **not** `Text` - MongoDB allows only one `$text` expression per query, so a `Text` id filter throws whenever a free-text `search` is also supplied.
- **Every parent cascades its delete**: the parent's controller overrides `DataCrudControllerBase.OnDeletedAsync` and calls its child repository's `DeleteAllFor<Parent>Async`, since a child is only ever reachable via the parent id and would
  otherwise be orphaned in MongoDB forever.
  The four cascade methods are one line each over `MongoDbRepositoryBase.DeleteAllByParentAsync`, which takes the parent-id **expression** (never an element-name string, same contract as `SortTitleField`) -
  don't re-hand-write the owner-scoped `DeleteMany`.
  Each cascade has a real-MongoDB `*ResourceTest` case; a mocked repository can't prove the filter matches.
- Never name a property bare `Type`: discriminators are `CarHistoryModel.EventType` (`CarHistoryType`), `HouseEventType`, `HealthEventType`, `TvShowModel.State`.
- **Car:** `CarHistoryModel.DeltaMileage` is real user-entered data (read off the trip computer), not derived - `CarMetricsService` cross-checks it against consecutive `Mileage` readings to flag typos/skipped entries.
  `CarMetricsService` (consumption only across a full refill, cost history, mileage warnings, next maintenance due) is a pure `AddSingleton` computation class exposed via `CarController.GetMetrics`, the same way
  `VideoGameController.RefreshReference` adds a per-item action to an entity's own controller.
- **House:** deliberately smaller than Car (owner priority: browsable insurance log + yearly cost review, no fuel/mileage, no reminders - tracked elsewhere).
  No due-date engine, only `HouseMetricsService.ComputeAnnualCostHistory`.
  `HistoryDate` is `DateOnly` (no same-day ordering need), so it reuses `CommonStorageMappings` instead of Car's hand-written `DateTime.SpecifyKind`/`ModalTimeText` machinery.
  One `Provider` field covers every category, unlike Car's Refuel/Maintenance split.
- **Health:** parent is a *person* (`HealthProfileModel.Name`, one per family member).
  `HistoryDate` is a full `DateTime` like Car's (appointment time is real data; reuses Car's ModalDate/ModalTimeText proxy pair), stamped UTC via an explicit `[MapProperty(Use = ...)]` in `HealthRecordStorageMapper`.
  The money model is the French reimbursement flow: `Price`, `PublicReimbursement`, `InsuranceReimbursement`, `NotCovered`.
  A record is *settled* exactly when `price - public - insurance - notCovered == 0` within `HealthMetricsService.BalanceTolerance` (0.005 - double arithmetic must never flag a settled record);
  anything else lands in `HealthMetricsModel.UnbalancedRecords` with the signed missing amount.
  **The balance rule lives only in `HealthMetricsService`** (`ComputeMissingAmount`/`IsBalanced`); the journal's "to check" badges come from the metrics' id list, never re-derived client-side. The detail page is journal-first and badge-only
  by owner feedback: no "to check" list, no chart, no per-row reimbursement column, and the yearly Paid/Reimbursed/OutOfPocket table sits *after* the journal.
  Both controllers are `MemberOnly`.
- Charts: axis/geometry math is shared in `BlazorApp/Components/Shared/SvgChartHelpers.cs` (`ChartGeometry`, `RenderAxes`, `EvenlySpacedIndices`); each page's own series-drawing loop stays local -
  forcing one shared renderer would be over-generalization.
  Chart CSS (`.kt-callout*`, `.kt-chart-*`, `.kt-sheet-table`, `.kt-legend-*`) is global in `app.css`, not scoped.
  House's yearly cost chart is a single-series bar chart plus a plain breakdown table, not a 6-color stacked chart.

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` implements the whole CRUD surface once, generically, reading the caller's `user_id` claim via `ControllerBaseExtensions.GetUserId()` to scope every query and stamp `OwnerId`.
Any new controller (CRUD or not) uses that same extension rather than re-reading the claim.

`ApiExceptionFilterAttribute` converts unhandled exceptions to JSON (`ArgumentException`/`ArgumentNullException` -> 400, else 500) and logs each one first, so a 500 leaves a server-side trail.

**Resilience:** every outbound third-party client (`TmdbClient`/`RawgClient`/`OpenLibraryClient`/`DiscogsClient`/`GoogleBooksClient`/`BnfClient`/`OmdbClient`) chains `.AddStandardResilienceHandler()` on its `AddHttpClient<...>()`
registration - retry, per-attempt and total timeouts, circuit breaker.
Give any new third-party client the same one-line treatment; never hand-roll it.
Covered once, representatively, by `ExternalProviderResilienceTest` against a stub handler.

`HostOptions.BackgroundServiceExceptionBehavior = Ignore` in `Program.cs` is a systemic backstop: by default an exception escaping any `BackgroundService.ExecuteAsync` stops the **entire host**.
A background service must still catch what it can anticipate; this only guarantees its bugs can't take down unrelated endpoints.

Not every endpoint is per-item CRUD.
Read-only cross-entity aggregations (`WatchNextController`, `WishlistController`, `StatsController`, `SystemStatusController`) live in `WebApi/Controllers/` as plain `ControllerBase`, with any real computation in `Domain/Services/`.
`WebApi/Import/` and `WebApi/ReferenceData/` still use the older colocated feature-folder shape; don't extend it to new code (migrating them is deliberately deferred).

**Wishlist sharing** is capability-URL based: `GET/POST /api/wishlist/shares`, `DELETE /api/wishlist/shares/{id}` (`wishlist_share`, one document per link, optional owner-only `Label`, `owner_id` non-unique, `token` unique), plus `GET
/api/wishlist/shared/{token}` - the app's **one deliberately anonymous read** (`[AllowAnonymous]`, backing a static-SSR `noindex` page at `/shared/wishlist/{token}`).
The 128-bit token *is* the access control (chosen over email invites: no mail infrastructure, works for unregistered recipients).
Revoking deletes one document, so per-recipient granularity holds; the delete is owner-scoped in the repository query.
`SharedWishlistApiClient` is registered **without** `AuthenticationTokenHandler` - the authenticated handler would bounce an anonymous recipient to login.
Both pages share one `WishlistRow` projection.

**A detached background job must run on `IHostApplicationLifetime.ApplicationStopping`, not an unbounded token.**
A pass takes minutes, so on shutdown it otherwise keeps working against a container being torn down: the singletons it depends on (the Mongo client, the HTTP clients, IGDB's rate limiter) are disposed out from under it and every
remaining step throws `ObjectDisposedException` - including the final job-store write, which leaves the job reading "Running" forever.
Confirmed in the running app, where a shutdown mid-pass surfaced as a disposed `TokenBucketRateLimiter` deep inside an IGDB call.
For the same reason, the per-item catches that keep one failing document from aborting a run (`ReferenceSyncService`, `ExploreCatalogueRefreshService`) exclude `OperationCanceledException`: a shutdown is not one failing document, and
swallowing it walks the rest of the page against a disposed container.

**Long-running work** runs as a background job, never a blocking request: buffer the input, start the work on a fresh `IServiceScopeFactory.CreateScope()` (the request scope is gone by then), return a job id, poll status.
`JobStore<TStage, TResult>` (`WebApi/Jobs/`) is backed by MongoDB (`background_job`, TTL 7 days), **not** memory - with several replicas, the replica answering a poll isn't the one running the job.
Owner id is checked in the repository query on every read.
A background task must resolve its own `JobStore` from its own scope.

### Auth, tiers and admin settings

- Firebase auth: cookie in `BlazorApp`, JWT bearer validated against Firebase in `WebApi`; `AuthenticationTokenHandler` attaches the bearer to outgoing calls.
- Authorization is **policy**-based, not `Roles=`: `AdminOnly` = `RequireClaim("role", "admin")`, `MemberOnly` = `RequireClaim("role", "member", "admin")`, registered in both `Program.cs` files.
  Firebase sends a plain `role` claim, not the `ClaimTypes.Role` URI.
  `BlazorApp`'s `AuthenticationController` copies it into the cookie principal at sign-in. Granting the first admin is a one-off `setCustomUserClaims` via the Firebase Admin SDK (see `CONTRIBUTING.md`).
- **Gotcha:** `AddJwtBearer` sets `MapInboundClaims = false` deliberately - otherwise the handler renames short JWT claim names to legacy `ClaimTypes.*` URIs and `RequireClaim("role", ...)` never matches, even though the token genuinely
  carries the claim.
  This is what once let the Blazor side show the admin nav link while the same user's API call 403'd. Leave it alone; don't assume a new custom claim is unaffected without checking.
- **Free preview tier:** anyone can sign in; an account with no `role` claim gets movies and TV shows only, capped at `Features:FreeTierItemLimit` per collection (default 20, guarded in `AppConfiguration.GetFreeTierItemLimit`), episodes at
  100x that (`EpisodeController.FreeTierLimitFactor` - generous on purpose, only to stop a raw-API caller flooding the database).
  Enforcement is API-side and two-layered: `[Authorize(Policy = "MemberOnly")]` on every restricted controller, plus the creation quota in `DataCrudControllerBase.Post` (403 with `{ error }`).
  `NavMenu.razor` hiding sections is UX, never security.
  `FreeTierTest` covers the quota and carries a reflection guard asserting each controller's expected policy - removing one is a failing test, not a silent giveaway.
- **Runtime-changeable global admin settings** live in one shared `app_setting` collection (single `_id: "global"` document, one field per setting) via `IAppSettingRepository`, which writes a targeted `$set` so unrelated settings are never
  clobbered.
  Reach for a new field here, not a new collection; use `AppConfiguration`/env vars only for deploy-time values.

### Reference data (shared, owner-less)

`tvshow_reference`, `movie_reference`, `book_reference`, `videogame_reference`, `album_reference` and `person_reference` hold provider metadata.
They are the one deliberate exception to "every collection has `owner_id`": public facts about a real work, stored once, pointed at by every tenant's `ReferenceId`.
Matching key is normalized title + year via `TitleNormalizer.Normalize` (shared with `TvTimeImportService` so the two never drift).

Providers: TMDB (TV/movie), IGDB / RAWG (video games), Discogs (albums), Google Books / Open Library / BnF (books), OMDb (IMDb ratings for TV/movie).

- These repositories do **not** extend `IDataRepository<TModel>`/`MongoDbRepositoryBase` (both are hard-constrained to `IHasIdAndOwnerId` + owner-scoped paged CRUD).
  Write a small purpose-built repository for any new owner-less collection.
- `ReferenceEnrichmentService` is one `partial class` split by file (`.TvShowsAndMovies.cs`/`.Books.cs`/`.VideoGames.cs`/`.Albums.cs`), five methods per domain:
  `TryLinkExisting<X>ReferenceAsync`/`TryAutoResolve<X>Async`/`Resolve<X>Async`/`Refresh<X>ReferenceAsync`.
  Shared helpers (`MergeMatchedAliases`, `ResolvePersonReferenceIdAsync`, `JoinGenres`) stay in the core file.
- It is the single place a title+year resolves to a provider id, and it propagates the result to every tenant's matching document via `I<X>Repository.SetReferenceLinkAsync`.
  Automatic resolution fires from `<X>Controller.OnCreatedAsync` and from `TvTimeImportService`, both on their own DI scope (never awaited inline - a bulk import must not block on a sequential chain of provider calls).
  The automatic path only acts on a **single, confident** search result; zero or several candidates leaves the item for the admin queue rather than guessing.
- `SetReferenceLinkAsync` also sets `Title`, `Year` and (per domain) `Author`/`Artist`/`Genre`/`Language` from the canonical record - linking corrects what the tenant typed, it doesn't just attach an id.
  Never overwrite with nothing: a field the provider has no value for is left alone.
  `VideoGameModel.Platform`/`State` describe this tenant's own copy and are never overwritten.
- `MatchedAliases` (`List<ReferenceMatchModel>`, tuple `(Title, Year, Creator, Isbn)`) records every combination ever confirmed to mean this work - both the canonical values and whatever the tenant searched with - merged, never overwritten.
  `UpsertAsync` guarantees the document's own title/year is present.
  Queries use `Builders.Filter.ElemMatch` so title and year must match on the *same* array element (an `AnyEq`-per-field approach would match a title on one alias and a year on another).
  Indexes are compound multikey over `matched_aliases.title`/`.year`.
  - `Creator` (Book/Album only) exists because a title+year collision is realistic there; it is always derived from the canonical provider response, never from tenant-typed text.
    TV/movie/game pass `null`.
  - `Isbn` (Book only) is recorded only on the alias that actually used it: the canonical alias (provider-reported) and the tenant-search alias are separate entries, and the search alias's `Isbn` is never backfilled.
- `Resolve<X>Async` checks for an existing reference document **by provider id first** (`FindByExternalIdAsync`), falling back to title+year/title-only.
  Title text alone can't prevent duplicates - two tenants (or an admin searching twice under different text) easily resolve the same entry through different strings.
  The provider id is invariant and authoritative.
- `*_tmdb_id`/external-id indexes are `unique: true` with `partialFilterExpression: { "external_ids.<key>": { $exists: true } }`.
  The application check is what's *supposed* to prevent duplicates; the database constraint is what guarantees it.
  The partial filter (not `sparse`, not a plain unique index) is required so documents missing the key don't all collide on one null.
  **One index per provider that can write that collection**, not one per collection: a document legitimately holds ids from several (a book linked through Open Library and later refreshed through Google Books, a game holding the RAWG id
  that linked it plus the IGDB id adopted later), and each id space needs its own guarantee.
  Books cover `googlebooks`/`openlibrary`/`bnf` and `person_reference` covers `tmdb`/`discogs`/`googlebooks`/`openlibrary`/`bnf` (`ResolvePersonReferenceIdAsync` is handed the *linking client's* `ProviderKey`, so an author or artist is
  created under whichever provider linked their work) - both were long declared for one provider only, which left the default book provider and every non-TMDB person with nothing but the application check.
- `TryLinkExisting<X>ReferenceAsync` is a second, cheaper path that never calls a provider: it only checks whether a matching document already exists.
  It backs `POST /api/<collection>/{id}/refresh-reference` - the "check for reference match" control shown **unconditionally** on every detail page to **any** authenticated user (it can only reuse a fact someone already established).
  It deliberately does **not** short-circuit on an existing `ReferenceId`: `Title`/`Year` are freely editable, and replacing a bad match (two real movies sharing a title is common) is the point.
  On a match it updates this tenant's own document directly, then also calls `SetReferenceLinkAsync` with the pre-edit title/year so other unresolved tenants benefit.
  On **no** match for an item that *was* linked, the link is cleared (`ReferenceId = ""`), which is exactly what returns it to the admin's unresolved queue.
  - **Gotcha:** the title-only fallback must run unconditionally, *including* when `Year` is null.
    An earlier version skipped it unless `Year is not null`, which is backwards - `FindByTitleYearAsync(title, null)` can only match a reference whose own year is also null, so any linked item with no year unlinked itself the instant the
    button was clicked.
    Confirmed by a real user on a valid, already-linked title.
- **Person dedup:** `person_reference` covers actors, book authors and album artists alike ("a named individual or group identified by a provider id"), deduplicated by provider person id via `ResolvePersonReferenceIdAsync`, never by name.
  References store only the id; `ReferenceDataController` hydrates names/`Cast`/`ProfileImageUrl` by joining server-side, which is why those DTO members are `[MapperIgnoreTarget]` and not plain mapped members.
- Images are **hotlinked from the provider CDN** (e.g. `https://image.tmdb.org/t/p/{size}{path}`, built once in the client and stored as a plain URL).
  This is TMDB's sanctioned pattern, so there is no local storage/static-file subsystem to operate.
- **Export/import:** `GET/POST /api/reference-data/export`/`import` round-trip all six reference collections as a zip of JSON arrays, so reference data is portable across environments instead of re-earned per deployment.
  `FindAllAsync()` exists solely to back the export (unpaged, acceptable because this data is small and shared); the export is a straight serialization of the models, so Mapperly's unmapped-member errors are what keep it field-complete.
  **The import matches every document by its provider id, never by the `_id` it was exported with** (`Domain/Services/ReferenceDataImportService.cs`, one generic algorithm over all six collections - the repositories share no base
  interface, so it takes `FindAllAsync`/`UpsertAsync` as delegates).
  An `_id` is local to the database that minted it: upserting by it meant the same real work (TMDB 1396) landed as a *second* document in any environment that had already resolved it on its own, which the unique partial indexes above
  reject outright - so an import into a non-empty database failed partway through, having already written everything before the collision.
  Matching on the provider id instead keeps the **target's** `_id`, which is what every tenant's `ReferenceId` and every `Cast[].PersonReferenceId` points at.
  Matching walks whatever keys a document carries, so no provider is named anywhere in the algorithm; an `_id` match survives only as the fallback for a document with no provider id at all.
  - **People are imported first, and every document citing them is re-pointed** at the id the target stores them under (`Cast[].PersonReferenceId`, `AuthorReferenceId`, `ArtistReferenceId`).
    Matching people by provider id without remapping would leave imported cast rows pointing at ids that don't exist in the target - a silent break, since a missing person just renders as no cast.
  - **A match merges, it doesn't replace.** The target legitimately knows things the export doesn't: `MatchedAliases` its own tenants' searches confirmed, and `Ratings` from a provider the exporting environment never called (an `imdb`
    value costs a metered OMDb call).
    Accumulated fields are unioned (`RatingsCheckedAt` keeps the *later* attempt per source - an older stamp must never move the re-attempt window backwards), and anything the import has no value for leaves the target's alone, the same
    "never overwrite with nothing" rule as `SetReferenceLinkAsync`.
  - **A provider id another document already claims is left behind and reported** (`SkippedExternalIds`, surfaced in the admin UI and logged), rather than written and taking the whole import down with it.
    It means the target holds two reference documents for one work, which only an admin can merge.
  - Covered by `ReferenceDataImportResourceTest` over real HTTP + real MongoDB, per domain and per provider - a mocked repository can't prove any of this, since the failure mode being prevented *is* the unique index firing.
- **Admin queue:** `ReferenceDataAdminController` (`AdminOnly`) handles manual search/link over a 5-way `ReferenceItemType`, using `ExternalId`/`Provider` (not TMDB-specific names) in its DTOs.

**Gotcha (`null` string filters, still relevant for old data):** "does this document have no reference link yet" cannot be `Eq(x => x.ReferenceId, null)`.
Documents written under the old AutoMapper stored `""` instead of BSON null and still exist.
Copy `TvShowRepository`/`MovieRepository`'s `UnresolvedFilter()` shape (null *or* empty) for any "is this string field unset" query. It fails silently - it just matches zero documents. Only a real-MongoDB integration test catches this class
of bug.

**Gotcha (null Find results):** every `Find*Async` that can legitimately return "nothing matched" must check `entity is null` **before** calling the mapper - Mapperly throws on a null source.
This applies to `MongoDbRepositoryBase.FindOneAsync` too, which every `GetById` 404 check depends on.
A mocked-repository unit test can never catch a regression here.

**Data-shape renames need a migration script**, not just updated `[BsonElement]` attributes.
`PosterUrl` -> `ImageUrl` silently blanked every pre-existing cover (72/87 TV, 343/353 movie references) until `scripts/migrate-poster-url-to-image-url.js` (idempotent `$rename`).
By contrast `TvShowModel.Status` -> `State` needed none, because the entity kept `[BsonElement("status")]`.
Run-once scripts follow that same idempotent style: `dedupe-matched-aliases.js`, `unset-tvshow-want-to-watch.js`, `migrate-is-owned-to-owned-versions.js`.

#### Per-provider findings (all confirmed against the real APIs)

- **IGDB** is unlike every other client here in three ways, all handled outside the client so it stays an ordinary typed `HttpClient`.
  It authenticates with a **Twitch app access token** rather than an api key (IGDB is part of Twitch and has no key of its own): `IgdbTokenProvider` caches one per process - not in MongoDB, deliberately unlike `OmdbCallBudget`,
  because a token is not a shared *quota* and Twitch issues one per request with several valid at once - and `IgdbAuthenticationHandler` attaches `Client-ID` + bearer, dropping the cached token and retrying **once** on a 401.
  It documents **4 requests/second**, paced by a `TokenBucketRateLimiter` held in a singleton (`IgdbRateLimiter`) rather than on the handler, which `IHttpClientFactory` rebuilds on every rotation.
  And queries are **POST bodies in Apicalypse**, not query strings - so a tenant-typed title is escaped before being embedded in a string literal, or a bare `"` would end the literal and let the rest parse as query syntax.
  - **Handler order is load-bearing: authentication, then resilience, then the rate limiter (outermost first).**
    The limiter goes *innermost* so its queue wait is covered by the resilience handler's total-request timeout - outside it, the wait is unbounded, because these clients deliberately set `HttpClient.Timeout` to
    `InfiniteTimeSpan` so the resilience pipeline owns the bound.
    Its queue is bounded for the same reason, and overflowing is cheap rather than fatal precisely because it sits inside: the 429 it synthesizes is retried with backoff,
    pacing a bulk pass instead of failing it.
    A retry also re-acquires a token, which is correct - a retry is another request against the ceiling.
  - **The renewal margin is capped at half the token's lifetime.** A fixed margin longer than the lifetime puts the renewal point in the past the instant the token arrives, so every call fetches a new one - caching nothing while doubling
    the traffic.
    Real Twitch app tokens last ~60 days, so this only bites on a short-lived or already-expired one; a unit test caught it.
  - Missing credentials are a supported state (`IgdbSettings.IsConfigured`, same optional shape as `OmdbSettings`): every call short-circuits to an empty result.
    It matters more here than for a secondary provider, since a hard
    requirement on the *default* provider's settings would take the whole API down on one unset value.
  - It reports **no Metacritic score**; `aggregated_rating` is IGDB's own aggregation of external critic scores, which is why it gets its own `igdbcritic` key.
  - **Gotcha: a stale field name fails silently.** `category` is gone from the API - IGDB neither returns it nor complains about it, so `where category = 0` parses fine and matches **zero** documents.
    A wrong field name in a `where` therefore empties an Explore ranking rather than erroring, and the refresh pass's "keep the previous catalogue when a pass returns nothing" rule would hide that for weeks.
    Same silent-empty-match family as the `ReferenceId` null/empty and `Lte(LastEnrichedAt, cutoff)` gotchas below.
    Its replacement is `game_type` (0 = main game).
    Field-level notes that don't shape the current code - the confirmed query shapes, `game_type` for a future advanced search, and what's deliberately unexplored - are in `docs/igdb-api-notes.md` rather than here.
  - **Explore deliberately does *not* restrict to main games**, though it could (`game_type = 0`, which a live probe confirmed removes "Elden Ring: Shadow of the Erdtree" and "The Last of Us Remastered" from the top five).
    A DLC or a remaster is a first-class thing to track here - the owner wants those records - so a well-reviewed expansion is a legitimate suggestion, not noise beside its parent.
    The vote-count floor is the ranking's only filter.
  - **`search` is relevance-ordered and genuinely noisy**: "Half-Life 2" returns three MMod variants above the canonical game, which is why admin search shows several candidates and automatic resolution only ever acts on a single one.
  - `first_release_date` is unix **seconds**, `cover.image_id` builds `https://images.igdb.com/igdb/image/upload/t_cover_big/{image_id}.jpg`, and critic counts run an order of magnitude below user counts
    (8-27 against thousands for the same titles), which is why the two rankings have very different vote floors.
- **Open Library** never sends `year` as a server-side filter: `first_publish_year` is the *work's* original year, not a tenant's edition, so filtering by it returns zero relevant results ("Killing Floor" + 2016 reprint).
  Year is still returned for display/tie-breaking.
  RAWG/Discogs keep their year filters; IGDB doesn't have one to keep (see its own entry above).
- **Open Library** searches via `q=` (relevance across titles/alternates), not `title=` (field-scoped exact match), which misses regional variants entirely -
  the US "Harry Potter and the Sorcerer's Stone" only matched near-empty stubs while the canonical UK-titled work carries 398 editions.
  Its `first_publish_date` is routinely absent from the work JSON, so `GetBookDetailsAsync` falls back to a single-document `q=key:{workKey}` re-query.
  Its `covers` array is contributed, not curated, so an unattractive cover is expected, not a bug.
  It exposes **no** reliable series field (the `person`/`subject_people` facet is a character name and doesn't generalize) - `BookModel.Series` is deliberately not auto-filled.
  Its `search.json` is also the slowest endpoint any provider here calls (36-41s, and 503s, measured during a real degradation), which is why its cross-provider **rating fallback is guarded, not just documented as best-effort**:
  `AddOpenLibraryRatingFallbackAsync` catches everything but `OperationCanceledException`, because an exception there used to escape `RefreshBookReferenceAsync`/`ResolveBookAsync` and discard a *complete* Google Books/BnF response -
  no upsert, no `LastEnrichedAt`, so those books led the staleness queue forever re-paying the timeout (see `docs/code-quality-findings.md`).
  Same rule as OMDb: an optional secondary provider may never fail the primary operation.
  And for the same reason both callers pass the **previously stored** openlibrary rating in: they rebuild `Ratings` from the linking provider, which never carries this value, so a lookup that never answered (failed, or no ISBN to ask with)
  keeps what is known while a real "no rating" response clears it - exactly `RebuildRatingsAsync`'s distinction for OMDb.
- **An optional narrowing parameter must never silently zero out results a broader search would find.** Discogs' `artist=` can fail to match its own indexing (disambiguation suffixes like `"Artist (2)"`, different formatting), returning
  nothing for a title that succeeds alone ("Born Pink").
  Both `DiscogsClient` and `OpenLibraryClient` retry once without the author/artist parameter when the constrained search comes back empty, rather than reporting a false "not found".
- **BnF**'s `"and (bib.author ...)"` CQL clause is not a strict intersection - title "La Peste" + author "Victor Hugo" returned genuine Hugo anthologies instead of zero. `BnfClient.SearchBooksCoreAsync` re-checks every candidate's parsed
  author client-side (`AuthorMatches`) and discards mismatches.
  BnF is the one XML/SRU client (Dublin Core per `srw:record`), its `ExternalId` is the bare ARK, its `dc:creator` "LastName, FirstName (dates). Role" is normalized to "FirstName
  LastName", and its ordinary records carry **no** cover art at all (expected, not a bug).
- **Google Books** is the book default (real synopses, covers, language, widest catalogue including manga).
  Uses `intitle:`/`inauthor:`; an `isbn` supersedes title/author entirely as the sole query (an exact identifier must not be "and"-ed with a fuzzy match).
  `CleanDescription` keeps the documented `b`/`i`/`br` HTML rather than flattening it: it decodes entities **first** (so an entity-encoded tag can't slip through and re-materialize), converts real `\n`/`\r\n` to `<br/>` **before** the
  allowlist pass (some descriptions break paragraphs with newlines only - "The Hobbit" rendered as one block), then reconstructs those three tags bare and strips everything else including attributes.
  That fixed allowlist-and-reconstruct (not a general sanitizer) is what makes `BookDetail.razor`'s `MarkupString` render safe - **never render a `MarkupString` from text that hasn't been through it.** It also upgrades
  `imageLinks.thumbnail` to `https://` to avoid mixed-content blocking.
- **Books are the one domain behind a provider-agnostic interface** (`IBookReferenceClient` with `ProviderKey`/`DisplayName`) and the one with several providers registered at once.
  `Program.cs` registers all of them (typed `AddHttpClient<TConcrete>` bridged via `AddTransient<IBookReferenceClient>` -
  `AddTransient`, so `IHttpClientFactory`'s handler rotation isn't defeated); registration order is the admin picker's display order. `BookReferenceClientRegistry` resolves a key (or the `ReferenceData:BookProvider` default, matched
  case-insensitively) to a client.
  The provider is a per-request admin choice, not a deploy-wide switch.
  `RefreshBookReferenceAsync` checks **every registered** provider's key against `ExternalIds`, not just the default's -
  otherwise a reference linked through another provider silently stops refreshing forever.
  `ReferenceEnrichmentService.Books.cs` never hardcodes a provider name, so a new provider needs only its own class plus one registration block.
  Admin provider buttons are selection-only; search is triggered by exactly one control.
- **Video games are the second multi-provider domain** (`IVideoGameReferenceClient`, `ReferenceData:VideoGameProvider`), added when RAWG went down: `IgdbClient` (`igdb`, the default) and `RawgClient` (`rawg`).
  The registry itself is shared - `ReferenceClientRegistry<TClient>` over `IReferenceProviderClient`, one class for both domains rather than one per domain.
  **Only the default provider is ever called on refresh** - the one deliberate divergence from `RefreshBookReferenceAsync`'s "refresh through whichever provider linked it".
  That rule is right for books, where every registered provider is reachable; this domain gained a second provider *because the first went down*, so falling back to it makes every not-yet-adopted reference pay a full
  retry-and-timeout cycle against a dead host on every pass - confirmed in the running app, which logged `GET api.rawg.io/api/games/...` for reference after reference.
  An operator who selects a provider must not see traffic to another one.
  A reference that can't be adopted keeps the data and the provider ids it already has, and is stamped as checked so the staleness queue rotates past it (never bumping `LastEnrichedAt` would park it at the head of that queue forever
  and starve everything behind it - the same re-walking-the-same-head failure the cap's ordering exists to prevent).
  RAWG therefore stays registered for two reasons only: an admin can still search/link with it, and its stored `rawg`/`metacritic` values keep rendering.
  - **A reference linked before the default changed adopts the new provider's id during the sync** (`TryAdoptDefaultVideoGameProviderAsync`), which is what carries a catalogue across a provider change with no migration script.
    Costs one search per not-yet-adopted reference per pass and nothing once adopted.
    The match rule is stricter than ordinary auto-resolution - exactly one candidate whose *normalized* title equals the reference's, with a compatible year -
    because a reference's title/year is canonical provider data, not tenant-typed text.
    Anything ambiguous is left for manual linking, same "don't guess" rule as everywhere else.
  - **A provider may only overwrite its own sources' ratings** (`MergeProviderRatings`, keyed on `IVideoGameReferenceClient.SupportedRatingSources`).
    An IGDB refresh must leave a reference's `rawg`/`metacritic` values alone: they are still rendered on the detail page and re-earning them would cost a call to a provider that may be down.
    A source the provider *does* own but no longer reports is correctly dropped - that's an answer, not an absence.
  - Unlike books, the details record carries the `Ratings` map *built by the client*: each game provider has two scores on scales that differ per provider, and that knowledge belongs to the provider rather than a switch in the enrichment
    service.
- TV/movie/album stay hard-wired to TMDB/Discogs (provider-named DTOs and `ExternalIds` keys on purpose - swapping one would be a redesign, not config).
- **Ratings:** `RatingSourceCatalog` declares each domain's selectable sources and code default (games `igdb`/`igdbcritic`/`metacritic`, movies/TV TMDB vs IMDb; defaults `igdb`/`tmdb`);
  **a source key is not a provider**: `rawg` stays declared with its scale-5 entry long after RAWG stopped being the default, because `ScaleOf` throws on an unknown source and references linked through RAWG still carry and display
  rawg-keyed values.
  Only its membership in the *selectable* list goes away, which makes `Resolve` ignore a stored RAWG-era override and fall back to the current default -
  and the existing recompute then re-stamps every tenant item, so the switch needed no migration script.
  IGDB reports no Metacritic score at all (its `aggregated_rating` is IGDB's own critic aggregation), so that number is never written under Metacritic's key;
  `ReferenceEnrichmentService.GetPrimaryRatingSourceAsync` reads the stored override.
  The admin card, `rating-sources` GET/PUT and `.../recompute` (bulk `SetReferenceRatingAsync`, no provider calls) are all domain-generic over `RatingSourceCatalog.SelectableDomains`, so a domain gaining a second source needs only a catalog
  entry.
  - **A tenant item's denormalized rating carries the source it came from** (`ReferenceRatingSource`, on all five models/entities/DTOs), alongside `ReferenceRating`/`ReferenceRatingScale`.
    Everything that writes the value writes the source: `SetReferenceLinkAsync`, `SetReferenceRatingAsync`, the `TryLinkExisting*` direct updates, and the clear-on-unlink/no-match branches (which clear all three).
    The source is stamped **even when that source has no value for the reference** - it records which source the copy was computed from, not where a number came from.
    Stamping it only alongside a value would leave every unrated item looking permanently stale and make the no-op below impossible.
  - **`recompute` does nothing when there is nothing to do:** it opens with `CountLinkedOnOtherRatingSourceAsync`, and returns `(0, 0)` without reading the reference collection at all when no linked item is on another source - the common
    case, since the button sits next to the source picker and gets clicked again "just in case".
    It used to read every reference document and fire one `UpdateMany` per document, all of them setting values that were already correct.
    An item stamped with nothing (linked before the field existed) counts as mismatched, so the first recompute backfills it and no migration script is needed.
    Deliberately **not** a value-drift repair - a value that moved while the source stayed put is the periodic sync's job, through the same `SetReferenceRatingAsync`.
  - **When it does have work, a batch is one projected read and one bulk write** (`RecomputeBatchSize` = 500, sizing both):
    `I<X>ReferenceRepository.FindRatingsAsync(afterId, limit)` projects `_id` + `ratings` and pages by an `_id` cursor, and `I<X>Repository.SetReferenceRatingsAsync` writes the page back as a single unordered `BulkWrite` of `UpdateMany`
    entries.
    Reading whole reference documents for two fields is the waste `FindExternalIdsAsync`/`FindStaleAsync` already exist to avoid (for TV it hauls each show's entire embedded episode guide), and a round trip per reference is what made the
    pass scale with the catalogue.
    **The tenant items are still re-stamped server-side inside each entry**, which is the property that matters as the user base grows:
    more users mean more documents written per reference, never more round trips, more payload, or more memory in the API.
  - The five identical propagation bodies now live once in `Infrastructure.MongoDb/Repositories/ReferenceRatingQueries.cs`, over the `IHasReferenceRating` entity interface (the four fields are named identically everywhere, so unlike
    `ExploreExclusionQueries` this needs no per-domain field expressions).
  - Books are the one domain with no selectable source: `BookPrimaryRating` reads whichever provider key the reference happens to store, and a reference with no rating at all genuinely has no source to name - which is why the source is
    nullable end-to-end.
  IMDb ratings come from **OMDb** keyed by the IMDb id TMDB exposes (IMDb has no public ratings API); it's native on `/movie/{id}`, appended via `?append_to_response=external_ids` for TV.
  OMDb is optional/best-effort: `OmdbSettings.ApiKey` is nullable and a missing section coalesces to empty, so a deployment without a key just keeps TMDB ratings.
  Full design in `docs/reference-ratings-plan.md`.
  - **OMDb's free tier is a hard 1000 calls/day, so every OMDb call goes through `OmdbCallBudget`** - not through a per-consumer constant.
    The count is one shared MongoDB document per (provider, UTC day) (`provider_quota`, `_id` = `"omdb:2026-08-03"`, TTL 7 days) reserved with the same atomic filtered upsert `LeaseRepository` uses, because an in-process counter would let
    every replica spend the whole allowance and the interactive path runs on whichever replica served the request.
    Reservation happens **before** the HTTP call, so an over-count is possible and an under-count is not - the safe direction against a hard limit.
    `Omdb:DailyCallBudget` (1000) and `Omdb:InteractiveReserve` (50) are the only knobs: `OmdbCallPriority.Interactive` (admin linking, Explore "add") may reach the whole allowance, `Background` (the sync backfill, then the Explore
    backfill, in that order on the same tick) stops short of the reserve, so a heavy batch day can never make a user's action come back unrated.
  - **`OmdbClient` never throws for anything OMDb or the network can do** - an unknown id, an unrated title, a spent quota, a timeout, a 5xx and an open circuit all come back as an `OmdbLookupResult`.
    It used to call `GetFromJsonAsync`, which throws on the **401** an exhausted key answers with, and that surfaced as a 500 from admin manual linking and from Explore "add" - both of which are supposed to treat IMDb as optional.
    Both of OMDb's 401s (`"Request limit reached!"` and a rejected key) write the day off via `OmdbCallBudget.MarkLimitReachedAsync`, which is what turns a blown quota from hundreds of doomed calls into one, and tells the other replicas.
  - **`OmdbLookupResult.Attempted` is the load-bearing half of that result.** "OMDb answered and has nothing for this title" may be recorded (it's what stops a backfill re-asking about the same titles);
    "we never got to ask" - no key, no budget, a failed request - must leave **no** stamp, or one exhausted afternoon writes those titles off for the whole re-attempt window.
  - **Gotcha:** the `/changes` short-circuit (`LastEnrichedAt is not null && Ratings.Count > 0`) means a reference enriched before IMDb existed would never backfill one -
    it has a tmdb rating so it short-circuits, but no stored imdb id because only a full fetch writes that.
    `BackfillImdbRatingAsync` resolves the id cheaply on the no-change path via `/{tv,movie}/{id}/external_ids` (one call, no season fan-out), stores it, then does one OMDb call.
    Self-correcting: once the id is stored, later passes skip the lookup.
  - **A title IMDb has nothing for is remembered, not re-asked every pass.** TV/movie reference documents carry `RatingsCheckedAt` (`ratings_checked_at`, source → last attempt), the same map and the same window as the Explore catalogue's -
    `RatingSourceCatalog.RatingReattemptAfter` (90 days) is the single declaration both read.
    Such a title never gains an `imdb` key, so there was nothing to short-circuit on and every pass past the 3-day cutoff paid a TMDB external-ids call **and** an OMDb call, forever.
    `BackfillImdbRatingAsync` checks the window **before** the id lookup, so both are skipped; the deferral is temporary, so a rating that appears later is still picked up.
    Only an attempt OMDb actually answered is stamped (see `OmdbLookupResult.Attempted` above), a re-resolve carries the existing stamps over rather than restarting them, and the Interactive paths ignore the window entirely -
    someone is waiting on that answer.
    No index and no migration: unlike Explore's map this is never a query filter, only read from a document the sync already loaded, and a missing field deserializes to "never attempted".
  - **Gotcha:** a full fetch rebuilds `Ratings` from TMDB, and the imdb value doesn't come from TMDB.
    Dropping it whenever OMDb couldn't be reached (no key, spent budget, failed request) discarded a rating that cost a call to obtain, on exactly the days the budget was tight.
    `RebuildRatingsAsync` (shared by both full-fetch paths) keeps the known value when the call never happened; "OMDb answered and has nothing" is a real answer and does clear it.
  - The admin picker is a `form-select` dropdown, not a button row - buttons render at different widths by text length.

### Keeping reference data fresh: periodic + on-demand sync

`ReferenceSyncBackgroundService` is a plain in-process `BackgroundService` on a 24h `PeriodicTimer` (with an immediate pass at startup), deliberately **not** a Kubernetes CronJob -
a second scheduled workload is real operational overhead for a job this cheap.
Every replica runs the loop but only one syncs per cycle: each tick tries `ILeaseRepository.TryAcquireAsync("reference-sync", Environment.MachineName, 1h)`, an atomic filtered upsert whose mutual exclusion is the `lease` collection's `_id`
uniqueness (covered by the real-Mongo `LeaseRepositoryTest`).
A replica dying while holding the lease delays the next pass by at most 1h against a 24h cadence.

`ReferenceSyncService.SyncStaleReferencesAsync(staleAfter, ...)` is the single sync algorithm, shared by the loop and the admin's `POST /api/reference-data/sync-now`.
**The two callers differ in nothing but the staleness windows, and those are declared once in `ReferenceSyncWindows`** (`Periodic` = 3 days for references / 7 days for Explore, `Forced` = `TimeSpan.Zero` for both).
`sync-now?force=true` re-checks everything; **without `force` it runs exactly what the background tick would have taken** -
which is why an admin run right after a forced one legitimately reports zero checked, the symptom that once read as "the background sync isn't running".
Restating either window at the second call site is what would let them drift apart silently, so `ReferenceSyncBackgroundService` reads `ReferenceSyncWindows.Periodic` rather than holding its own constants (`ReferenceSyncWindowsTest` guards
it).
One failing document never aborts the run - each is caught and logged individually.
It is **one** generic loop over five one-line domain arms (`SyncDomainAsync`), the same shape as `RecomputeReferenceRatingsAsync`; it used to be the identical loop copy-pasted per domain.

**Which documents a pass takes, and in what order, is `I<X>ReferenceRepository.FindStaleAsync(cutoff, limit)`** -
a server-side filter and sort (shared once in `Infrastructure.MongoDb/Repositories/ReferenceStalenessQueries.cs`), replacing a `FindAllAsync()` that read every reference document into memory each tick -
for TV, including every show's whole embedded episode guide - to then discard most of them.
Never-enriched first, then least-recently-enriched, capped at `MaxDocumentsPerDomainPerPass` (500).
The order is what makes the cap safe: a pass always takes the stalest end, so whatever it doesn't reach leads the next one.
Unordered, a capped pass would re-walk the same head forever and the tail would be refreshed never.

**Gotcha:** "never enriched" cannot come from the date comparison.
MongoDB compares within a type, so `Lte(LastEnrichedAt, cutoff)` matches neither a null nor a missing field, and the documents most in need of a pass would be exactly the ones the query could never return.
`Eq(field, null)` matches both null and missing (also covering documents written before the field existed), and ascending order then puts them first for free - BSON sorts null ahead of every date.
Same silent-empty-match family as the `ReferenceId` null/empty gotcha below; only the real-Mongo `ReferenceStalenessRepositoryTest` catches it.
`last_enriched_at` is indexed on all five reference collections for this query.

`RefreshTvShowReferenceAsync`/`RefreshMovieReferenceAsync` lead with a cheap pre-check: TMDB's per-id `/changes?start_date=...` (one call, no season fan-out).
If nothing changed, only `LastEnrichedAt` is bumped and the full details + per-season cast calls are skipped.
A reference with no `LastEnrichedAt` always does the full fetch.
**Divergence:** IGDB/RAWG/Discogs/book providers expose no `/changes` equivalent, so those domains always full-fetch once past the staleness cutoff, and their `*Updated` counts always equal their `*Checked` counts.

**Gotcha:** the service is registered unconditionally but only works when `Features:IsReferenceSyncEnabled` (default `true`), checked fresh every tick.
`KestrelWebAppFactory` overrides it to `false` via `ConfigureAppConfiguration` (in-memory source added last, so it wins).
`UseSetting` was tried and silently doesn't work for a top-level-statement minimal-hosting `Program.cs`.
Without the override, every integration fixture fired real TMDB calls.
**Use `KestrelWebAppFactory<Program>` for any new integration fixture**, even one that doesn't need real Kestrel networking, so it inherits this for free (a bare `WebApplicationFactory<Program>` bypasses it and already bit
`AuxiliaryResourceTest`).

### TV Time import

`POST /api/import/tv-time` (background job, see "Long-running work").
Findings, all confirmed against real export data:

- `seen_episode_source.csv` alone is a drastically incomplete episode history (only written from TV Time's episode-detail screen).
  `TvTimeImportService` also reads `tracking-prod-records.csv` and `-v2.csv`, merged and deduplicated per (show, season, episode), earliest date wins.
- `followed_tv_show.csv` is not a complete show list either (confirmed with "The Pitt").
  `ImportEpisodesAsync` creates shows on the fly from watch events; don't reintroduce a "skip if not already followed" check.
- Movies **do** have watch dates: `tracking-prod-records.csv` carries `entity_type == "movie"` rows with `type` watch (`FirstSeenAt`), towatch (`WantToWatch`, only when there's no watch event) and follow.
  `-v2.csv` carries no movie data.
  If a field looks suspiciously absent, re-check the real export before documenting it as a limitation - twice now an "unrecoverable" gap was just unparsed.
- **Idempotency is by stable id, never by title.** Enrichment rewrites `Title` to the canonical name after the first import, so title matching duplicated everything on re-import.
  Every imported show/movie is stamped with `TvTimeId` (`IHasTvTimeId`, carried through entity/DTO and round-tripped on edits since `UpdateAsync` is a full replace): TV Time's show id, or the per-movie tracking `uuid`.
  When the export carries no id, `ResolveTvTimeId` synthesizes a deterministic `tvtime_title:<normalized-title>` from the **export** title (which enrichment never touches), and `BuildIdByTitle` maps titles to ids across the id-bearing files
  first so title-only files resolve to the same id.
- `UpsertIndex<TModel>` matches by `TvTimeId` first; a title fallback fires only for a pre-existing record with no id yet, which is adopted and back-filled once (`BackfillTvTimeIdAsync`).
  A record carrying a *different* id is left alone.
- **On a match the record is left untouched** - a re-import must never clobber edits made in the app afterwards (rating, notes, favorite, corrected title/year).
  Don't reintroduce an update-on-existing path.
  Only new items are created; counts are deduped by reference identity.
- **Gotcha:** a CSV property present in only some of the three files' headers (e.g. `TvShowId`) needs `[Optional]` from `CsvHelper.Configuration.Attributes` on top of not being C# `required` - CsvHelper's header validation throws regardless
  of nullability.
  Only a realistic fixture catches this.

### Watch Next

`WatchNextService.ComputeInProgressShows(shows, episodes, referencesByShowId)` reports a show only if its `State` is `TvShowStatus.Current` **and** the linked reference's episode list has an entry after the last one watched, compared by
`(SeasonNumber, EpisodeNumber)` - never by title or air-date order - whose `AirDate` has already passed or is unset.
A show with no `ReferenceId` or no reference document is excluded rather than guessed at.
The controller only fetches reference documents for shows that are `Current` and linked.
The DTO reports the confirmed next episode (`InProgressShowDto.Next*`); this is real episode-guide data, not the old "+1" heuristic that shipped confirmed-wrong results.

`FilterMoviesToWatch` excludes a movie once `FirstSeenAt` is set even if `WantToWatch` is still true - the flag can go stale, so the exclusion happens at read time.

**`WantToWatch` is movie-only; TV shows deliberately don't have it.** The flag once existed on `TvShowModel` with no consuming feature and was removed everywhere (plus `scripts/unset-tvshow-want-to-watch.js`).
If a "shows I want to start" surface is ever wanted, build a real Watch Next section, not a dead flag.

`TvShowDetail.razor`'s episode checklist applies the same `AirDate is null || AirDate <= today` filter before grouping into seasons, so an announced-but-unaired season simply doesn't appear. It's a full watch-through checklist once the show
has a `ReferenceId` (checking a box creates an `Episode` with `WatchedAt = today`, unchecking deletes it), falling back to the recorded-episodes-only view with a manual add form when it doesn't -
a deliberate scope boundary, since episode counts are unknowable without reference data.

### Explore (discovery)

`ExploreController`/`ExploreService` (`/explore`) suggests top-rated titles the caller doesn't track, with one-click add and dismiss/undo.
Movie, TvShow, VideoGame only; Book/Album 400 (no best-of listing to read).

- **The discovery list originates from the provider, never from local `*_reference` collections.** That was the original implementation's core mistake:
  a reference document only exists because someone already tracks that title, so a local query can only re-suggest what's already owned.
  Sources: TMDB `/{movie,tv}/top_rated`, the video game provider's own ranked query (IGDB `sort {rating|aggregated_rating} desc`).
- **The read path doesn't call the provider, though: it pages `explore_catalogue`, a materialized copy of each ranking** written weekly by `ExploreCatalogueRefreshService`.
  The ranking is a *global* fact - every user's page is the same list, only the exclusions below differ - so fetching it per request was duplicated work (a page load, and then *every* add and dismiss topping the list back up, re-pulled the
  same
  provider pages), and the few pages a request could afford is what once capped Explore at roughly the top 100 titles.
  Owner-less like the `*_reference` collections, and the same exception to "every collection has `owner_id`" for the same reason.
  `CatalogueDepth` (1000/ranking) is the "how far can you scroll" knob and costs one provider call per page of depth *per week*, nothing per request.
- A **ranking** is a domain plus an *ordering*, not a domain plus a displayed rating - `ExploreRankings` is the single declaration, derived from `RatingSourceCatalog` so a new source needs no second list.
  TMDB publishes one top-rated list whatever the rating source is, so movies/TV have one ranking each; a game provider genuinely sorts differently per source, so video games get one ranking per source *its active provider supports*.
  **`ExploreRankings` is an injected service, not a static class**, precisely because the video game answers - discovery provider, rankings, displayable sources - come from whichever provider that deployment registered as the default.
  `DisplaySource` is the other half: a source the catalogue cannot carry (Metacritic, once the discovery provider stopped reporting it) falls back to the ranking's own number rather than blanking every card, while IMDb for movies/TV stays
  displayable because the refresh pass backfills it.
  A pass also prunes entries whose `(type, ranking)` is no longer maintained at all - `DeleteStaleAsync` only prunes *within* a ranking it just rewrote, so a ranking abandoned by a provider change would otherwise sit stale forever.
  Ordering still follows the admin-selected primary rating source (`RatingSourceCatalog.Resolve`, no Explore-specific setting) - it now selects which stored ordering to read.
  Movies/TV under **IMDb** are the awkward case (IMDb has no catalogue API): the entries stay in TMDB's order and IMDb only fills in the displayed number, deliberately **not** re-sorted by it -
  partial IMDb coverage would float unrated titles
  to the top.
  That number is backfilled by the refresh pass (each entry costs a TMDB + an OMDb call, spent from the shared `OmdbCallBudget` - the pass sizes its query to whatever the reference sync left of the day's allowance rather than a hardcoded
  per-domain cap, which had to assume the worst about the other consumer), so an entry deep in the ranking can legitimately have no IMDb rating yet and shows none - the same
  semantics as the old per-request lookup coming back empty.
  Attempts are stamped whenever OMDb actually answered, whether or not it produced a value; without that, the handful of titles OMDb has nothing for would consume the whole budget every pass and coverage would never advance.
  A call the budget refused is **not** stamped and simply retries next pass.
  `app_setting.explore_use_tmdb` forces movies/TV back onto TMDB's vote and skips the backfill entirely; it's read only when IMDb won the resolve, so it can't leak into the game domain.
- **Refresh safety, all deliberate:** the pass upserts one `$set` per rating key (never replacing the `ratings` map, or an ordinary refresh would discard the expensively-obtained IMDb value);
  it prunes what it didn't rewrite **only after completing**, so a failed or empty pass leaves last week's ranking serving rather than emptying Explore;
  and staleness is read from the ***oldest*** `refreshed_at` in a ranking, not the newest - a pass that died halfway leaves its written entries freshly stamped, and taking the newest would read that as "just refreshed" and skip the retry.
- The refresh rides `ReferenceSyncBackgroundService`'s existing 24h tick and lease on its own 7-day staleness window, rather than adding a second scheduled workload;
  the admin's `POST /api/reference-data/sync-now` covers it on the same window pair (`?force=true` rebuilds every ranking, the default only what is past 7 days), so there's no separate Explore admin endpoint.
  Counts land in `ReferenceSyncResultDto`.
- **Gotcha:** neither provider has a curated top-rated endpoint, and ordering a whole catalogue by a plain average ranks a single-vote unknown above every classic.
  IGDB reports a vote count per game, so its ranking uses a real floor (`MinUserRatingCount`/`MinCriticRatingCount`) - and that floor is deliberately its only filter, since DLC and remasters are things this app tracks in their own right.
  RAWG exposed no vote count at all, which is the only reason its client had to approximate one:
  `GetTopRatedGamesAsync` constrains the pool server-side with `metacritic={MinMetacritic},100` - "reviewed by the professional press at all" is the closest equivalent of a minimum vote count and costs no extra call.
  `MinMetacritic` is the knob to raise.
  Don't filter client-side instead: the paging loop stops on an empty page, so a filter that can empty one would silently truncate results.
- **The "already have it" exclusion needs both halves**: by provider id (`FindLinkedReferenceIdsAsync` resolved to those documents' `ExternalIds[provider]`) and by normalized title (`FindDistinctTitlesAsync` + `TitleNormalizer`), because
  automatic resolution gives up on multiple candidates, so a manually-added item may have no link at all and would be re-suggested forever.
  Two different works sharing a title collapse under the fallback - an accepted trade.
  `IExploreSourceRepository` declares both projections once; `ExploreExclusionQueries` implements them for every domain, each repository contributing only a field expression.
  Resolving those reference ids to provider ids goes through `I<X>ReferenceRepository.FindExternalIdsAsync`, a **projected** read over `external_ids` alone - **not** `FindByIdsAsync`, which fetches whole documents (synopsis, cast, matched
  aliases, and for TV the entire embedded episode guide) to yield one string each.
  An owner tracking a few hundred linked shows would otherwise drag every episode of every season across on every Explore request.
  `FindByIdsAsync` stays for `ReferenceImageHydrator`, which genuinely needs more of the document.
- `explore_dismissal` is keyed `{owner_id, item_type, external_source, external_id}` (unique) on the *provider's* id, since a suggestion usually has no reference document yet.
  `external_source` is the **discovery** provider (`tmdb`/`igdb`), not the rating source - an IMDb-ranked movie is still identified by a TMDB id, and RAWG/TMDB ids are both plain integers with nothing but an explicit provider to keep them
  apart.
  `ExploreRankings.DiscoverySource` is the one place a domain's provider is named.
- **Adding goes through `POST /api/explore/{type}/add/{externalId}`, not the ordinary create**: it creates the item then calls `Resolve*Async` with the *exact* provider id, awaited, so the card only disappears once genuinely linked.
  The ordinary create's auto-resolve is a title search that only links on a single candidate, which acclaimed titles routinely fail.
  Free-tier quota is enforced here via `FreeTierQuota.CheckAsync`.
  The controller is plain `[Authorize]` (movies/TV are free tier) with video games member-gated per request (`RequireAccessTo`, 403); the page hides the tab behind `<AuthorizeView Policy="MemberOnly">` and falls back to Movies -
  hiding is UX, the API is enforcement.
- **Paging is a rank cursor (`?after=`), never skip/limit**, because the per-caller exclusions are applied *after* the ranked read: with a skip, every title filtered out of one page shifts the next page up and silently drops suggestions.
  `ExploreSuggestionPageDto` carries `NextCursor` (null = ranking exhausted) and `CataloguePending` - "not built yet", right after a fresh deployment, is an empty list too but means the opposite of "you've seen everything" to a user.
  The service advances the cursor over *every entry examined*, not just those kept, so a run of already-owned titles is never re-read.
  A page may come back shorter than requested and still have more behind it.
- `ExplorePage.razor` keeps the active tab in `?tab=`, holds one `TabState` (items + cursor) per tab, and appends below the current cards rather than reshuffling - both for the explicit "Load more" and for the automatic top-up after an
  add/dismiss, which share `AppendNextPageAsync`.
  That top-up used to re-request page 1 and diff it, so it re-paid for the same suggestions on every single action and could only backfill from titles already shown; continuing from the cursor asks for what actually comes next and costs one
  indexed read.
  Add and dismiss share one `ActAsync`.

## Blazor app

`InventoryPageBase<TDto>` centralizes list/paging/search/filter state and calls `InventoryApiClientBase<TDto>`.
A concrete page supplies only its `Api` and `CloneItem`, plus a `protected virtual ExtraQuery` override for its own filters.
Pages that aren't generic CRUD lists (detail pages, Watch Next, Import) build their own layout on the shared `kt-*` classes in `app.css`, with their API clients in their own feature folder.

**List state lives in the URL query string** (`?search=&page=&sort=` plus lowercase per-filter params), read back via `[SupplyParameterFromQuery]`.
Search/filter/pagination clicks never call `LoadAsync` - they navigate via `ApplyQueryChanges`/`ToggleFilter`/`SetFilter`, and the reload happens once in `OnParametersSetAsync`.
This is what makes browser-back from a detail page restore the exact list position, and it means a click and a back/forward share one code path.
A new filter therefore needs exactly three things: a `[SupplyParameterFromQuery]` property, an `ExtraQuery` entry (API-facing key, e.g. `IsFavorite`), and a button calling `ToggleFilter`/`SetFilter` with the URL param name (e.g.
`favorite`).
Don't add a mutate-then-`LoadAsync` handler.

**List ordering is deterministic everywhere.** `MongoDbRepositoryBase.FindAllAsync` sorts every page read, defaulting to `_id` descending (ObjectIds embed creation time, so no created-at field is needed) with `_id` appended as tie-break
under every other key - an unsorted skip/limit page can duplicate or drop items across pages.
`PagedRequest.Sort` carries a `ListSort` key (`title`, `rating`) end-to-end; a repository opts in by overriding `SortTitleField`/`SortRatingField` with an **expression**, never an element-name string (`Car.Name` stores as `commercial_name`,
which a string sort would silently miss).
Unknown keys fall back to newest-first.
The title sort attaches a per-query `Collation` ("en", strength 2) for case/diacritic-insensitive ordering with no shadow field and no new indexes (per-owner subsets are small).

- **Gotcha:** MongoDB rejects a collation combined with a `$text` filter.
  This is safe today only because every `GetFilter` searches via regex `Contains` (the base's `builder.Text` default is effectively dead) - a future `$text`-searching repository must gate the collation.
- `InventoryList`'s search box keeps a deliberate local copy of the text (so a parent re-render racing fast typing can't revert characters) and adopts an external `Search` change only when it didn't originate from its own `OnSearchChanged`
  - read the sent/received tracking in `OnParametersSet` before touching it.

**Gotcha:** a `string`-typed component `[Parameter]` needs the `@` prefix - `Title="_movie.Title"` binds the **literal text**, not the value.
Razor only infers C# when the parameter type couldn't accept a string literal (`Year="_movie.Year"` on `int?` works unprefixed).
It compiles and renders fine; the bug shows up only in the data, which is how `InlineReferenceLinker` once searched TMDB for the literal `_movie.Title`.
Always write `Title="@_movie.Title"`.

**Scaling is an app-level design here, not an infrastructure assumption** - the app may sit behind a Cloudflare tunnel with no cookie affinity, so nothing may rely on sticky sessions.
`DataProtection:MongoDb:*` (opt-in) persists the key ring via `DataProtection/MongoDbXmlRepository` so cookies and antiforgery tokens decrypt on every replica; without it multi-replica cookie auth breaks.
This is the only reason `BlazorApp.csproj` references `MongoDB.Driver` (it still never references `Domain`/`Infrastructure.MongoDb`).
`Features:IsWebSocketsOnlyEnabled` (default `true`) starts the circuit with `skipNegotiation` + WebSockets-only, pinning a circuit to the pod owning its state;
set it `false` only behind a proxy that can't pass WebSockets, and stay single-replica there.

### Theme

Dark-only: no light theme, no toggle.
`App.razor` sets `data-bs-theme="dark"` statically on `<html>`, server-rendered, so there's no flash on first paint or between navigations.
The previous light+dark version (with `theme.js`, a nav toggle, and a JS initializer re-applying the attribute) was removed at the owner's request.
**Don't reintroduce `data-bs-theme` as something client-side JS sets** - enhanced navigation re-fetches and diffs the whole document, stripping anything not in the server-rendered markup.
System-ui fonts only, no webfonts.

A JS initializer (`wwwroot/Keeptrack.BlazorApp.lib.module.js`, autoloaded by name - never add a manual `<script>` tag) is the place to hook `blazor.addEventListener('enhancedload', ...)` if any future client-side DOM state needs
re-applying.
It was removed when the theme made it unnecessary.

**Icons are plain Unicode with text presentation** (`◈ ✓ ✕ ★ ▶ ↻ ⌂ ⚙ ♪ ◼ ▭ ▬ ◆`), never a codepoint that renders as a color emoji - a color glyph reads as unpolished among monochrome UI following `--kt-text`/`--kt-accent`.
**Gotcha:** looking like a plain symbol isn't enough.
`⭐` (U+2B50) and `👁` (U+1F441) have `Emoji_Presentation=Yes` and render in color everywhere; they were replaced by `★` (U+2605) and `▶` (U+25B6).
Check a new codepoint's default presentation before using it, never append U+FE0F, and drop a symbol entirely rather than force a semantic near-match when the label text already carries the meaning.
`.kt-icon-spin` rotates a plain glyph for in-progress states instead of an hourglass emoji.

**Before assuming an `app.css` rule applies, check for a scoped `{Component}.razor.css`** - CSS isolation compiles an extra scope attribute, so a scoped selector always wins over an equally-specific shared one.
This is why `ReconnectModal` kept its scaffolded white/blue colors despite an `app.css` override; the scoped file has to be edited.

## Tests

- `test/WebApi.UnitTests` - xunit v3, pure logic (import parsers, `WatchNextService`, metrics services, `FreeTierTest`, resilience wiring).
  Mapper validation is compile-time now (Mapperly diagnostics), not a test.
- `test/WebApi.IntegrationTests` - xunit v3 against a real Kestrel host (`KestrelWebAppFactory<Program>`) and real MongoDB.
  `ResourceTestBase` gives typed `GetAsync`/`PostAsync`/`PutAsync`/`DeleteAsync`/`PostFileAsync`, an `Authenticate()` that gets a real Firebase bearer token, and `AuthenticatedUserId` (the `user_id` claim read from the payload without
  signature checking, since the API validates on every call).
  `TvTimeFixtureZipBuilder` builds a synthetic export in memory - never commit a real personal export.
  `SyncNow_PollingReachesACompletedResult` self-skips unless `REFERENCE_SYNC_POLL_ENABLED=true`.
- `test/Testing.Shared` - shared hosting/Firebase infrastructure for both suites, not a test project.
  `KestrelWebAppFactory<TEntryPoint>` takes its env-var name and config overrides as constructor parameters so each host supplies its own.
- `test/BlazorApp.PlaywrightTests` - Playwright e2e (`Microsoft.Playwright.Xunit.v3`'s `PageTest`, plain facts, no Gherkin; see `docs/playwright-e2e-tests-plan.md`). Every test self-skips unless `E2E_ENABLED=true`, so a plain `dotnet test`
  stays green without browsers.
  `E2eFixture` (`[AssemblyFixture]`) hosts both apps in-process, signs in once for the whole run, and seeds a synthetic book reference.
  `Pages/PageBase` holds nav locators and `Open<X>Async()` helpers;
  `ListPage` is one class parameterized by route/title for all ten list pages; detail-page title inputs share `.kt-title-input` (no `data-testid` needed), while a few unlabeled Add-form fields do carry a minimal `data-testid`.
  Movie/TvShow/VideoGame/Album smoke tests link real titles against real providers through `InlineReferenceLinker`, so `Tmdb__ApiKey`/`Rawg__ApiKey`/`Discogs__Token` are hard-required (the fixture fails fast if missing).
  `WatchNextSmokeTest` is in a `DisableParallelization` collection - it aggregates across the whole shared tenant, so parallel classes' traffic raced its assertions.
  `E2eFixture` is shared by parallel classes, so `ApiHttpClient` is built with `LazyInitializer.EnsureInitialized` (a plain `??=` caused a real intermittent failure).
  `ExploreSmokeTest` seeds `explore_catalogue` directly through the hosted `IExploreCatalogueRepository` (`End2EndFixture.SeedExploreCatalogueAsync`, self-hosted mode only - it self-skips under `E2E_TARGET_URL`):
  the ranking is otherwise only ever written by the weekly refresh pass, which the e2e host never runs, so a seeded ranking *is* the whole ranking and low ranks land on the page's first fetch.
  Every seeded entry is removed by external id at the end of the test, as is every dismissal it records; only the `Add` case uses a real TMDB id (adding resolves the reference from the exact provider id, which a synthetic id can't).
  Video games link through IGDB, the domain's default provider, so `Igdb__ClientId`/`Igdb__ClientSecret` are hard-required and `Rawg__ApiKey` deliberately is not - no e2e path reaches RAWG unless a test picks it explicitly.
  **Gotcha: a smoke test must stay in the default *list* view.** `ItemGridCard` covers its card with an empty Bootstrap `stretched-link` anchor (the clickable area is the `::after` pseudo-element), so the `<a>` itself has no size and
  Playwright refuses to click it - "element is not visible", on an element it just resolved by accessible name.
  `ListPage.OpenItemAsync` therefore only works in list view, which is what every list page renders by default; switching to thumbnails mid-test breaks it.
  `MobileScreenshotTest` is an assertion-free visual harness behind `E2E_SCREENSHOTS=true`, capturing every page at 390x844 into `E2E_SHOTS_DIR`.
  See `CONTRIBUTING.md` for the full `E2E_*` surface and the three run modes.
- Assertions use `AwesomeAssertions` (FluentAssertions-compatible); data via `Bogus`.

### Which database a suite writes to, and leaving it as it was found

The integration and Playwright suites run against a **real, long-lived MongoDB** - there is no per-test throwaway database.
Two rules follow, and both have been broken expensively.

**Point every suite at a dedicated database, never `keeptrack_dev`.** `Infrastructure__MongoDB__DatabaseName` selects it (`keeptrack_integrationtests`/`keeptrack_e2e` by convention).
When unset it fails *silently*: the in-process host runs as `Development` and falls back to `appsettings.Development.json`, i.e. the database the developer browses in the app.
That's how it accumulated 180 `test-lease-*` documents, 65 `Export Test Actor` person references and stray `E2e Smoke *` items - easy to hit, since running a filtered subset means exporting the runsettings vars yourself.
`Testing.Shared/Hosting/TestDatabaseGuard.EnsureExplicitTestDatabase` now fails the run fast, called from `KestrelWebAppFactory`'s constructor and from `End2EndFixture` in self-hosted mode.

**Every test removes what it created, on success and on failure.** Not tidiness: `scripts/mongodb-create-index.js` enforces uniqueness, so yesterday's leftover fails today's run with a duplicate key.
**Register cleanup at the moment of creation**, never as a per-test `try`/`finally` - a `finally` only covers what was created before the `try` opened, and "create two fixtures, then open the try" leaked whenever the second create failed.

- `DatabaseTestBase` holds the registry: `TrackCleanup(Func<Task>)`, `TrackDocument(collection, id)`, `TrackDocumentsWhere(collection, filter)` for owner-scoped singletons with no visible id (`user_preference`).
  `ResourceTestBase` adds the HTTP-level `CreateAsync` (POST + register), `TrackResource`, and `TrackResourcesMatching<TDto>` for imports whose ids the test never learns.
  `SmokeTestBase` mirrors it for Playwright (`TrackOpenItem` reads the id from the detail page URL, `CreateItemAsync`, `TrackItemsMatching`).
- `DisposeAsync` **drains** the registry rather than iterating a cached count, since `TrackResourcesMatching` discovers and registers ids at cleanup time.
- Cleanups run under `CancellationToken.None`, never `TestContext.Current.CancellationToken` - that token is cancelled exactly when a test times out, which is when leftovers are most likely.
- **Deleting what a test did *not* create is forbidden, with exactly one exception: a scenario whose precondition is "the tenant doesn't already hold this item".** `ExploreSmokeTest`'s add is the only one -
  Explore's whole contract is to hide what the caller already tracks, so a database that already holds that title shows no suggestion card at all and the test can never pass, however well it cleans up afterwards.
  `SmokeTestBase.RemoveItemsMatchingAsync` (the immediate form of `TrackItemsMatching`) clears it up front, matched on the full title rather than the short search term.
  It is only acceptable because `TestDatabaseGuard` refuses any database name containing `dev`/`prod`/`staging`/`preprod`, so the suite can only ever run against a throwaway one.
  Never reach for it to paper over a missing cleanup - **a failure that leaks is what makes the next run fail**, which is exactly how this test taught the lesson: it died before `TrackOpenItem` claimed the id, and every later run then
  found an empty Explore page.

**Gotcha, and why this class of bug persists: a delete filter that matches nothing looks exactly like a delete that worked.** `Builders<TEntity>.Filter.Eq("_id", id)` with a `string` id against an `ObjectId` `_id` matches nothing, deletes
nothing and reports success - those tests passed for months while 65 documents piled up.
The typed `Eq(x => x.Id, id)` works; the string-field-name form does not.
`TrackDocument` sidesteps it by filtering over `BsonDocument` and converting the id to an `ObjectId` when it parses (`lease`/`background_job` ids are genuine strings and simply don't).
**Never take a passing exit status as proof cleanup worked - verify with a document-count diff across the run.**

**Reference documents created by linking a *real* provider title are deliberately left in place** (TMDB's "The Terminator", its cast rows, a Google Books volume):
shared canonical facts, deduplicated by provider id, so a re-run reuses them and deleting only forces a re-fetch.
Synthetic fixtures are the opposite - made-up ids accumulate and collide with the unique partial index, so they must always be removed and must generate their external id per test (`TestExternalId.New()`;
two classes both inserting `tmdb: "1"` is a real duplicate-key failure).
Fixed-title real-provider smoke tests (Movie/TvShow/VideoGame/Album) do clean up, since a leftover there is an accumulating duplicate.

Deleting a TV show **does** cascade to its episodes, like `Car`/`House`/`HealthProfile`, so a test that marks an episode watched only has to delete the show (it used to have to clean up the episodes itself).

**A document with no list page is the easiest one to leak.** `explore_dismissal` is the current example: dismissing a suggestion writes an owner-scoped document that appears in no UI, nothing else ever deletes, and whose only visible effect
is that the title silently never comes back in that account's real Explore feed.
`ExploreResourceTest`/`ExploreSmokeTest` both register the undo (`DELETE /api/explore/{type}/dismiss/{externalId}`) at the moment they dismiss, never afterwards.
Same for `explore_catalogue` seeds (see the Explore testing note below).

## Code style

- Enforced by `.editorconfig`: 4-space indent for C#/Razor, LF endings, `var` everywhere, braces required, `_camelCase` private instance fields, `s_camelCase` private static, PascalCase otherwise.
  Avoid `this.`.
- Primary constructors are the norm for controllers, repositories and API clients.
- Nullable reference types are on across `src`; use `required` for non-nullable properties with no sensible default.
- Public `WebApi.Contracts` DTOs and controllers carry XML doc comments - they feed the generated OpenAPI/Scalar docs.
- Markdown: **never wrap lines**.
  Formatting is applied separately with `npx neatmd .`.
  **Never run markdownlint** (or `npx markdownlint-cli2`), not even to check an edit.

## CI

GitHub Actions (`.github/workflows/ci.yaml`) on push/PR to `main`: a git/markup lint job, a .NET quality job (build, test with coverage, SonarCloud, FOSSA) gated on app changes, and a container image scan for both Dockerfiles.
Equivalent pipelines exist for GitLab CI and Azure DevOps.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms.
Hold every change to this standard, not just new code.

- **No duplicated algorithms or logic.** Duplicated data *shapes* (a Model, Entity and Dto mirroring the same fields) are fine and expected; duplicating the logic over them is not.
  Shared behavior belongs in a base class or shared method, following `DataCrudControllerBase<TDto, TModel>` / `MongoDbRepositoryBase<TModel, TEntity>` / `InventoryPageBase<TDto>` / `OwnedItemImportCommitCoordinator` / `SvgChartHelpers`.
- **Every non-trivial piece of logic needs a test**, especially per-type overrides like `GetFilter` - the least-reused code in the solution and where bugs have historically hidden.
- **Don't guess when you don't have the info.** Resolution, imports and Watch Next all leave something unresolved rather than shipping a confident wrong answer.
- **A mocked-repository unit test cannot prove serialization or MongoDB semantics.** Anything about filters, collation, null storage or index behavior needs a real-MongoDB integration test.
- Before proposing a fix, verify current best practice for the specific library/framework version in use (MongoDB driver filter semantics, current ASP.NET Core guidance) rather than relying on older patterns from training data.
- Known findings from past reviews, including which are confirmed bugs versus intentional behavior, are tracked in `docs/code-quality-findings.md`.
  Check it before re-reporting, and update it when an item is fixed.
