# AGENTS.md

Guidance for coding agents working in this repository.

## Project overview

Keeptrack is source-available (PolyForm Strict 1.0.0, see `LICENSE`, not open source).
It lets users save and review everything they read, watch, listen to or play: books, movies, TV shows, albums, video games, plus car, house and health journals.

Three-tier .NET 10 / C#: `BlazorApp` (Blazor Server UI), `WebApi` (ASP.NET REST API), MongoDB.

## Writing style

These rules apply to Markdown, code comments, commit messages, chat replies, and any prose in scripts.

**One sentence per line.**
A line break only ever happens at the end of a sentence.
Never wrap a sentence across two lines.
Act as if there is no maximum line length: wrapping is handled by the editor, not by hard newlines.

**Never use the em dash (`—`) or the en dash (`–`).**
Use a colon when introducing an explanation, a comma when joining clauses, or a full stop and a new sentence.
This applies to prose, code comments, table cells, and error message strings.

**Never use the second person.**
No "you", no "your", not even in placeholders such as `<your-token>`, which should read `<token>`.
The documentation describes the repository, it does not address a reader.

**Other conventions.**
Use `ini` as the fence language for `.properties` blocks, never `properties`.
Prefer `>` over `→` when describing UI navigation, for example **Project Settings > Quality Gate**.

## Repository conventions

Shell scripts are named in `snake_case` and committed with the executable bit set (`git update-index --chmod=+x path/to/script.sh`).
A script committed as `100644` fails on a fresh clone even though it works locally.

The root `README.md` stays as short as possible.
Shared content lives in `docs/` and is linked, never copied.
Contributor-facing material lives in `CONTRIBUTING.md` and must only provide guided steps to be up and running.
Superseded plans, finished migrations and dated assessments live in `docs/archived/`.

Target platform is Linux, including WSL2, and `bash`.

## Hard rules

**Never run a third party container image on this workstation.**
No `docker run` and no `docker pull` of any image not published by Docker or by GitHub.
Security scanners are invoked as locally installed binaries, never containerised.
When a tool has no local install path, it is left unwired and recorded in `docs/backlog.md`.

**Never run linters.**
No `markdownlint`, no `yamllint`, no formatter, no `npx` invocation of any of them.
Linting is run by the repository owner, outside of agent sessions.

**Only GitHub Actions published by `github` or `docker` are allowed in workflows.**
Reusable actions owned by this account, in `../github-workflow-parts`, are also allowed.
Anything else is replaced by an explicit command that downloads the official release binary and verifies its SHA256 checksum.

**The harness is Node.js and bash only.**
Python scripts or code is not allowed.

**Test before code when applicable.**
Tests are written before the implementation and versioned as the source of truth for expected behavior.

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

Integration tests need Firebase test-user credentials and MongoDB settings, as env vars or in a `Local.runsettings` at the repo root (template in `CONTRIBUTING.md`, never commit it).

**Gotcha:** `--settings Local.runsettings` cannot be combined with `--filter-method`/`--filter-class`.
`--settings` switches `dotnet test` to legacy VSTest mode, which rejects the MTP filter flags and silently runs zero tests (exit code 5).
For a filtered subset, load the runsettings env vars into the shell instead:

```powershell
[xml]$rs = Get-Content Local.runsettings
$rs.RunSettings.RunConfiguration.EnvironmentVariables.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | ForEach-Object { Set-Item -Path "env:$($_.Name)" -Value $_.InnerText }
dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "Keeptrack.WebApi.IntegrationTests.Resources.WishlistResourceTest.*"
```

On bash, `scripts/load-runsettings.js` is the equivalent:

```bash
eval "$(node scripts/load-runsettings.js)"
dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "*WishlistResourceTest*"
```

**Never convert those values into plain `NAME=value` lines and source them.**
Sourcing runs each value through shell expansion, so a secret containing `$` silently loses everything from the `$` to the next non-word character.
It surfaces as Firebase answering `INVALID_PASSWORD`, which reads as a wrong password rather than a mangled one, and a real session lost an hour to it.
The script single-quotes every value, escapes any embedded `'`, decodes XML entities and skips commented-out variables.
The PowerShell form above is immune for the same reason: `Set-Item -Value` never re-parses what it is given.

A full unfiltered run can still use `--settings`.

## Architecture

Layered / clean architecture across small single-purpose projects (`src/*`), `Domain` at the center, nothing references outward.

Project                  | Depends on                                             | Responsibility
-------------------------|--------------------------------------------------------|---------------
`Common.System`          | none                                                   | Cross-cutting primitives: `IHasId`, `IHasIdAndOwnerId`, `PagedRequest`, `PagedResult<T>`, `TitleNormalizer`, `ListSort`, `RefuelCostCheck`.
`Domain`                 | `Common.System`                                        | Business models (`Models/*Model`), repository interfaces (`Repositories/I*Repository`), pure services (`Services/`). No persistence or web concerns.
`Infrastructure.MongoDb` | `Domain`                                               | BSON `Entities/`, `Repositories/`, `Mappers/`.
`WebApi.Contracts`       | `Common.System`                                        | Public REST DTOs (`Dto/`), shared with `BlazorApp` so the client deserializes without duplicate classes.
`WebApi`                 | `Infrastructure.MongoDb`, `Domain`, `WebApi.Contracts` | Controllers, DTO mappers, DI, JWT auth, OpenAPI/Scalar.
`BlazorApp`              | `Common.System`, `WebApi.Contracts`                    | Blazor Server UI over HTTP, never references `Domain`/`Infrastructure.MongoDb`.

### Data model conventions

Every user-owned entity implements `IHasIdAndOwnerId` at all three layers, one class each.
Mapping is compile-time via [Riok.Mapperly](https://github.com/riok/mapperly): one `[Mapper]` partial per pair in `Infrastructure.MongoDb/Mappers/` (`IStorageMapper<TModel, TEntity>`) and `WebApi/Mappers/` (`IDtoMapper<TDto, TModel>`).

- Unmapped members are **build errors** (`RMG012`/`RMG020` escalated in `.editorconfig`).
  Add an explicit `[MapperIgnoreSource]`/`[MapperIgnoreTarget]` for a member a direction genuinely doesn't need, never leave one unmapped.
- **A single-word entity property is stored camelCase, not snake_case**: `CamelCaseElementNameConvention` is registered globally in `InfrastructureServiceCollectionExtensions`, so only multi-word members carry an explicit `[BsonElement("public_reimbursement")]`.
  Repository code is unaffected because every query names the field with an **expression**, which resolves through the class map.
  Anything written by hand against raw names must use the stored one: an index declaration or a `$rename` migration naming `Specialty` instead of `specialty` matches zero documents and reports success.
- `OwnerId` uses `[MapValue(nameof(Model.OwnerId), "")]` on DTO to model (a plain ignore won't compile, it's `required`).
  The placeholder is overwritten server-side from the caller's claims in `DataCrudControllerBase`, never trusted from client input.
- Read-only feature controllers (`WatchNextController`, `WishlistController`, Car/House metrics, `ReferenceDataController`) use a small one-directional Model to Dto mapper class injected by its concrete type.
- An enum used in a Domain model needs a **separate** copy in `WebApi.Contracts` (Contracts doesn't depend on Domain).
  Keep member names identical, DTO mappers set `EnumMappingStrategy.ByName`, so drift becomes a build diagnostic.
  Mongo entities reuse the Domain enum directly.
- A nullable DTO member mapping to a `required` model member needs an explicit fallback: `CommonDtoMappings.ToRequiredString` (attached via `[UseStaticMapper]`).
  `CarDto.EnergyType` (nullable, and a different enum type) has its own hand-written `[UserMapping]` wrapping the generated `ByName` conversion.

### Adding a new trackable item type

Follow `Book`/`Movie`/`Album`/`TvShow`/`VideoGame`/`Car` as the template.
A new type touches every layer:

1. `Domain/Models/<X>Model.cs` plus `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` (explicit `[BsonElement("snake_case")]`) plus `Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs` (XML doc comments feed the OpenAPI spec).
4. `WebApi/Controllers/<X>Controller.cs`: a one-line class extending `DataCrudControllerBase<TDto, TModel>`.
   CRUD logic is never duplicated per controller.
5. Register the repository and storage mapper in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`, register the DTO mapper in `Program.cs`.
6. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` (extends `InventoryApiClientBase<TDto>`) plus `Pages/<X>.razor`/`.razor.cs` (extends `InventoryPageBase<TDto>`, overrides `ListRoute`).
   The Add form carries only identity fields, everything else is edited on the detail page, which starts with a `<Breadcrumb/>`.
   List rows are uniform media rows rendered by `InventoryList` (cover thumb, title, per-type `MetaTemplate`, delete icon), the whole row opens the detail page and there is deliberately no per-row edit modal.
7. Declare indexes in `scripts/mongodb-create-index.js` (natural-key uniqueness, query shapes, partial indexes for sparse flags).
8. If reference-linked: the DTO implements `IReferenceLinkedDto` (server-hydrated `ImageUrl`, ignored both ways in the mapper), the reference repository gets a batched `FindByIdsAsync`, and the controller overrides `OnListMappedAsync` to hydrate covers via `ReferenceImageHydrator`, one batched lookup per page and never one per item.

**Gotcha:** a DTO used by `InventoryPageBase<TDto>` can never have a `required` member.
That base is constrained `where TDto : IHasId, new()`, and any `required` member breaks `new()` (`CS9040`).
That's why `BookDto.Title`, `CarDto.Name` and friends are nullable while their models are `required`: a language limitation, not an inconsistency to fix.
DTOs with no `InventoryPageBase` usage (`CarHistoryDto`) mirror `required` in full.

### Ownership: owned versions, never a stored flag

An item is owned exactly when it has at least one owned copy.
The old stored `is_owned` boolean was removed as a duplicate flag that could drift.

- `Movie`/`TvShow`/`Book`/`Album` embed `List<OwnedVersionModel>` (`owned_versions`): `CopyType` (`Physical` first so it's the default, or `Digital`), optional `Price` (`decimal`/Decimal128, currency-agnostic), `AcquiredAt` (`DateOnly` via `CommonStorageMappings`), `Vendor`, and free-text `Reference` (edition/order number, unrelated to `ReferenceId`).
- Video games have **no** `OwnedVersions`: their per-platform entries already carry a `CopyType` and *are* the copies, so a game is owned when `Platforms` is non-empty.
- `IsOwned` survives only as a filter-only query parameter, repositories translate it to `SizeGt(OwnedVersions/Platforms, 0)` and the `*_owned` partial indexes match that predicate.
  Storage mappers ignore it both ways.
- Detail pages share `OwnedVersionsEditor`/`OwnedVersionFields` (`Components/Inventory/Shared/`), list rows derive the Owned badge from `OwnedVersions.Count > 0` (video games show platform badges instead).
  A new copy is a draft card with Save/Cancel (nothing persists until Save), an already-saved copy auto-saves on change like every other detail field.
  Removing a saved copy uses `Components/Shared/TrashIcon.razor` plus `ConfirmModal`, skipped when the copy is entirely empty.
- `VideoGamePlatformModel.ProductName` is the store's own product/edition text for that copy, distinct from `Title`.
  It renders through `OwnedVersionFields`' `ExtraFields` slot rather than being added to `IOwnedCopyDto`, since no other type has the concept.
  The component's columns are unnumbered `col-md` so an extra column re-shares width instead of wrapping.
- Migration for existing data: `scripts/migrate-is-owned-to-owned-versions.js`, then re-run `scripts/mongodb-create-index.js`.

### Bulk store/retailer transaction imports

Three importers of the same shape, controller in `Controllers/` and pure parsing/computation in `Domain/Services/`:

- `AmazonImportController`/`AmazonOrderPreviewService`: order-history CSV, keeps only what's Amazon-specific (`FormatOrderReference` = ASIN plus order id, `BuildAmazonProvenanceNotes`).
- `GenericVideoGameImportController`/`GenericVideoGameImportService`: video-game-only transaction CSV (PSN's GDPR export today, `Vendor` is a per-row column so any store with that shape works).
- `GenericImportController`/`GenericImportService` (`POST /api/import/generic`, `MemberOnly`): **the store-agnostic default, extend this rather than adding another store-specific importer.**
  It reads a canonical, case-insensitive column set (all optional except `Title`) the user reshapes any export into.
  A `Type` column sets each row's `ImportMediaType` directly (`ParseMediaType` tolerates "TV Show", "Video Game", "Film", "Jeu"), a blank or unrecognized value falls back to the per-row picker rather than guessing.
  Aliases cover real headers (`Product Name` to Title, `ASIN`/`SKU` to `ProductId`, `Total Amount` to Price, `Product Condition` to Condition).
  `Vendor` (store name) and `Website` are **separate** columns: `Vendor` becomes the copy's Vendor, `Website` becomes the copy's `Reference`.
  `Condition` is preserved on the copy's `ProductName` field (a deliberate difference from Amazon, owner's request).

Shared engine, never duplicated: `Domain/Services/OwnedItemImportMergeService.cs` (`ComputeCommitPlan`/`FindImportedReferences`, matching by normalized title via `TitleNormalizer`, merging within the same commit batch), returning `Domain/Models/ImportCommitPlan.cs`.
Per-type create/merge orchestration lives once in `Domain/Services/OwnedItemImportCommitCoordinator.cs`: both multi-type controllers pass a flat `List<OwnedItemImportInput>` and read back per-type `OwnedItemImportCommitCounts`.

`ImportMediaType` exists as two identically-named enums (`Domain.Models` and `WebApi.Contracts.Dto`, mapped by name), a controller importing both namespaces must alias one, same as `CopyType`.

**Gotcha (confirmed against a real PSN export):** a transaction/order id pair is *not* unique per line the way Amazon's ASIN is.
One transaction can bundle several products (three "Far Cry 4" DLC packs, distinguishable only by Product Name), so a reference built from transaction plus order id made bundled lines collide and be silently skipped as duplicates.
Any import reference or dedup key needs a per-product disambiguator: Product Name here, ASIN for Amazon, order id plus product id for generic.

**`VideoGamesCreated`/`VideoGamesMergedInto` count distinct items, not selected rows, so they undercount rows on purpose.**
Rows sharing a normalized title consolidate into one item within a batch.
`ImportCommitPlan<TModel>.OwnedCopiesAdded`/`...CommitResultDto.RowsImported` is the true per-row count (`RowsImported + Skipped` always equals rows submitted) and `SkippedRowTitles` names what was skipped, so the UI can show a reconciling "X of Y selected rows imported".

### Child entities (1-to-many owned by another entity)

`CarHistory`/`Car`, `Episode`/`TvShow`, `HouseHistory`/`House`, `HealthRecord`/`HealthProfile` are separate top-level collections referencing the parent by id (`car_id`, `tv_show_id`), not embedded arrays.
Deliberate: these grow unbounded per parent, and features query them across *all* of a user's parents at once (Watch Next), which needs a plain indexed query rather than `$unwind`.
Embed only genuinely small, always-together, never-queried-alone data (`TvShowReferenceModel.Episodes` is the counter-example: bounded, always fetched whole, never queried across shows).

- `GetFilter` on a child repository filters the parent id with `Eq`, **not** `Text`: MongoDB allows only one `$text` expression per query, so a `Text` id filter throws whenever a free-text `search` is also supplied.
- **Every parent cascades its delete.**
  The parent's controller overrides `DataCrudControllerBase.OnDeletedAsync` and calls its child repository's `DeleteAllFor<Parent>Async`, since a child is only ever reachable via the parent id and would otherwise be orphaned forever.
  The four cascade methods are one line each over `MongoDbRepositoryBase.DeleteAllByParentAsync`, which takes the parent-id **expression** (never an element-name string, same contract as `SortTitleField`).
  Each cascade has a real-MongoDB `*ResourceTest` case, a mocked repository can't prove the filter matches.
- Never name a property bare `Type`: discriminators are `CarHistoryModel.EventType` (`CarHistoryType`), `HouseEventType`, `HealthEventType`, `TvShowModel.State`.

**Car.**
`CarHistoryModel.DeltaMileage` is real user-entered data (read off the trip computer), not derived, and `CarMetricsService` cross-checks it against consecutive `Mileage` readings to flag typos or skipped entries.
`CarMetricsService` (consumption only across a full refill, cost history, mileage warnings, next maintenance due) is a pure `AddSingleton` computation class exposed via `CarController.GetMetrics`, the same way `VideoGameController.RefreshReference` adds a per-item action to an entity's own controller.

- **A refuel's station is a reference, not free text** (`CarHistoryModel.StationId` to `car_station`, owner-less by the same deliberate exception as the `*_reference` collections: a station at an address is a public fact).
  It replaced a `station.brand_name` embedded on every entry plus that entry's own copy of the station's city, postal code and coordinates, so a refuel no longer carries a location at all.
  `CarHistoryController.OnListMappedAsync` hydrates `StationBrandName`/`StationCity` for display through `CarStationHydrator`, one batched lookup per page.
  Maintenance and Other entries keep their own location and their free-text `Garage`: they have no station to inherit one from, so there is nothing to de-duplicate.
  Migration: `scripts/migrate-car-history-station.js` (a refuel that named no station keeps its location and is *reported*, never silently blanked), then re-run `scripts/mongodb-create-index.js`.
- **Members create stations inline, admins curate them.**
  The natural key is normalized brand name plus normalized city plus postal code (`FindByNaturalKeyAsync`, unique index), and `POST /api/car-stations` is find-or-create so the picker can post on every keystroke-committed name without minting duplicates.
  A member refuelling somewhere new must never wait on an admin, the same split as reference auto-resolution and its admin queue.
  `/admin/car-stations` (`AdminOnly`) is where a station gains its real city and coordinates and where duplicates are merged.
  `city_normalized` is `""` (never null or missing) for a cityless station, or the unique index would collapse every one of them onto a single key.
- **A station in use cannot be deleted, only merged** (409 naming the count): a station is only reachable through an entry's `StationId`, so deleting one blanks every referencing refuel's location with nothing to recover it from.
  The merge re-points every entry (`RepointStationAsync`) **before** deleting the absorbed document, exactly like the video-game reference merge, and fills only the survivor's *gaps*.
  The city is adopted only when it doesn't collide with a third station's key: gaining a city is cosmetic, losing the merge to a duplicate-key 500 is not.
- **The refuel form checks the total against what was pumped, and only warns** (`Common.System/RefuelCostCheck`, live as the user types, which is why it sits in the one project `BlazorApp` and `Domain` both see).
  Fuel type, volume, unit price and cost sit in one row so the three numbers that must agree are read together.
  A receipt legitimately differs from the pump (a car wash on the same ticket, a loyalty discount), so it never auto-fills or blocks, but a *missing* cost when one is computable does count as a mismatch.
  The tolerance is derived from what the pump's display rounds away (volume to 0.01, unit price to 0.001) rather than being a flat constant, which would either false-positive on a big tank or wave a real error through on a small one.
- `CarHistoryDto.FuelCategory` ("SP95-E10") is offered through `SuggestInput` fed by `GET /api/car-history/fuel-categories`, the same "suggest what has already been typed" shape as gear categories, both over the one `MongoDbRepositoryBase.FindDistinctValuesAsync`.

**House.**
Deliberately smaller than Car (owner priority: browsable insurance log plus yearly cost review, no fuel, no mileage, no reminders).
No due-date engine, only `HouseMetricsService.ComputeAnnualCostHistory`.
`HistoryDate` is `DateOnly` (no same-day ordering need), so it reuses `CommonStorageMappings` instead of Car's hand-written `DateTime.SpecifyKind`/`ModalTimeText` machinery.
One `Provider` field covers every category, unlike Car's Refuel/Maintenance split.

**Health.**
The parent is a *person* (`HealthProfileModel.Name`, one per family member), and both controllers are `MemberOnly`.
`HistoryDate` is a full `DateTime` like Car's (appointment time is real data, reusing Car's ModalDate/ModalTimeText proxy pair), stamped UTC via an explicit `[MapProperty(Use = ...)]` in `HealthRecordStorageMapper`.
The money model is the French reimbursement flow: `Price`, `PublicReimbursement`, `InsuranceReimbursement`, `NotCovered`.
A record is *settled* exactly when `price - public - insurance - notCovered == 0` within `HealthMetricsService.BalanceTolerance` (0.005, double arithmetic must never flag a settled record), anything else lands in `HealthMetricsModel.UnbalancedRecords` with the signed missing amount.
**The balance rule lives only in `HealthMetricsService`** (`ComputeMissingAmount`/`IsBalanced`), the journal's "to check" badges come from the metrics' id list and are never re-derived client-side.
The detail page is journal-first and badge-only by owner feedback: no "to check" list, no chart, no per-row reimbursement column, and the yearly Paid/Reimbursed/OutOfPocket table sits *after* the journal.
**`Specialty` and `Practitioner` are free text with a suggestion dropdown over what this account has already recorded** (`GET /api/health-records/suggestions` to `SuggestInput`, the same shape as gear categories and fuel grades).
The two lists travel in one `HealthRecordSuggestionsDto` rather than one endpoint each, because the form needs both the moment it opens.
Owner-scoped, and unlike `car_station` this must never become a shared catalogue: a specialty or a doctor's name is one account's medical history, not a public fact about a place.

**Charts.**
Axis and geometry math is shared in `BlazorApp/Components/Shared/SvgChartHelpers.cs` (`ChartGeometry`, `RenderAxes`, `EvenlySpacedIndices`), each page's own series-drawing loop stays local because forcing one shared renderer would be over-generalization.
Chart CSS (`.kt-callout*`, `.kt-chart-*`, `.kt-sheet-table`, `.kt-legend-*`) is global in `app.css`, not scoped.
House's yearly cost chart is a single-series bar chart plus a plain breakdown table, not a 6-color stacked chart.

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` implements the whole CRUD surface once, generically, reading the caller's `user_id` claim via `ControllerBaseExtensions.GetUserId()` to scope every query and stamp `OwnerId`.
Any new controller, CRUD or not, uses that same extension rather than re-reading the claim.

`ApiExceptionFilterAttribute` converts unhandled exceptions to JSON (`ArgumentException`/`ArgumentNullException` to 400, a failed provider call to 502, else 500) and logs each one first, so a failed request leaves a server-side trail.

**A third-party provider that timed out, exhausted its retries or tripped its circuit breaker is a 502, not a 500** (`TimeoutRejectedException`/`BrokenCircuitException`/`HttpRequestException`, logged as a warning).
Reporting it as 500 claims the fault is ours and makes an outage indistinguishable from a defect here.
The only outbound HTTP an action makes is to the reference providers, so nothing else lands in that bucket.

**The 502's `{ error }` says what the provider actually did.**
`DescribeUpstreamFailure` reports the provider's own status ("The external provider returned 503 (ServiceUnavailable)."), unreachable, timed out, or circuit-open, instead of echoing the raw framework message.
The client half matters just as much: `BlazorApp/Components/Shared/ApiResponseExtensions` (`EnsureSuccessOrThrowAsync`/`ReadJsonOrThrowAsync`, throwing `ApiRequestException` with `IsUpstreamProviderFailure`) reads that body, because `HttpResponseMessage.EnsureSuccessStatusCode` throws with only the status line and **discards the body**.
**Use those extensions, not `EnsureSuccessStatusCode`/`GetFromJsonAsync`, wherever a failure is shown to a user.**
`InlineReferenceLinker` then names the provider, quotes that detail, and, when the failure was upstream and the domain has more than one provider, points at the picker instead of only saying "wait and try again".

**Resilience:** every outbound third-party client (`TmdbClient`/`RawgClient`/`OpenLibraryClient`/`DiscogsClient`/`GoogleBooksClient`/`BnfClient`/`OmdbClient`) chains `.AddStandardResilienceHandler()` on its `AddHttpClient<...>()` registration: retry, per-attempt and total timeouts, circuit breaker.
Give any new third-party client the same one-line treatment, never hand-roll it.
Covered once, representatively, by `ExternalProviderResilienceTest` against a stub handler.

`HostOptions.BackgroundServiceExceptionBehavior = Ignore` in `Program.cs` is a systemic backstop: by default an exception escaping any `BackgroundService.ExecuteAsync` stops the **entire host**.
A background service must still catch what it can anticipate, this only guarantees its bugs can't take down unrelated endpoints.

Not every endpoint is per-item CRUD.
Read-only cross-entity aggregations (`WatchNextController`, `WishlistController`, `StatsController`, `SystemStatusController`) live in `WebApi/Controllers/` as plain `ControllerBase`, with any real computation in `Domain/Services/`.
`WebApi/Import/` and `WebApi/ReferenceData/` still use the older colocated feature-folder shape, don't extend it to new code (migrating them is deliberately deferred).

**Wishlist sharing** is capability-URL based: `GET/POST /api/wishlist/shares`, `DELETE /api/wishlist/shares/{id}` (`wishlist_share`, one document per link, optional owner-only `Label`, `owner_id` non-unique, `token` unique), plus `GET /api/wishlist/shared/{token}`, the app's **one deliberately anonymous read** (`[AllowAnonymous]`, backing a static-SSR `noindex` page at `/shared/wishlist/{token}`).
The 128-bit token *is* the access control, chosen over email invites because there is no mail infrastructure and it works for unregistered recipients.
Revoking deletes one document so per-recipient granularity holds, and the delete is owner-scoped in the repository query.
`SharedWishlistApiClient` is registered **without** `AuthenticationTokenHandler`, since the authenticated handler would bounce an anonymous recipient to login.
Both pages share one `WishlistRow` projection.

**A detached background job must run on `IHostApplicationLifetime.ApplicationStopping`, not an unbounded token.**
A pass takes minutes, so on shutdown it otherwise keeps working against a container being torn down: the singletons it depends on (the Mongo client, the HTTP clients, IGDB's rate limiter) are disposed out from under it and every remaining step throws `ObjectDisposedException`, including the final job-store write, which leaves the job reading "Running" forever.
For the same reason, the per-item catches that keep one failing document from aborting a run (`ReferenceSyncService`, `ExploreCatalogueRefreshService`) exclude `OperationCanceledException`: a shutdown is not one failing document, and swallowing it walks the rest of the page against a disposed container.

**Long-running work** runs as a background job, never a blocking request: buffer the input, start the work on a fresh `IServiceScopeFactory.CreateScope()` (the request scope is gone by then), return a job id, poll status.
`JobStore<TStage, TResult>` (`WebApi/Jobs/`) is backed by MongoDB (`background_job`, TTL 7 days), **not** memory: with several replicas, the replica answering a poll isn't the one running the job.
Owner id is checked in the repository query on every read, and a background task must resolve its own `JobStore` from its own scope.

### Auth, tiers and admin settings

- Firebase auth: cookie in `BlazorApp`, JWT bearer validated against Firebase in `WebApi`, `AuthenticationTokenHandler` attaches the bearer to outgoing calls.
- Authorization is **policy**-based, not `Roles=`: `AdminOnly` = `RequireClaim("role", "admin")`, `MemberOnly` = `RequireClaim("role", "member", "admin")`, registered in both `Program.cs` files.
  Firebase sends a plain `role` claim, not the `ClaimTypes.Role` URI.
  `BlazorApp`'s `AuthenticationController` copies it into the cookie principal at sign-in, and granting the first admin is a one-off `setCustomUserClaims` via the Firebase Admin SDK (see `CONTRIBUTING.md`).
- **Gotcha:** `AddJwtBearer` sets `MapInboundClaims = false` deliberately, otherwise the handler renames short JWT claim names to legacy `ClaimTypes.*` URIs and `RequireClaim("role", ...)` never matches even though the token genuinely carries the claim.
  This is what once let the Blazor side show the admin nav link while the same user's API call 403'd.
  Don't assume a new custom claim is unaffected without checking.
- **Free preview tier:** anyone can sign in, and an account with no `role` claim gets movies and TV shows only, capped at `Features:FreeTierItemLimit` per collection (default 20, guarded in `AppConfiguration.GetFreeTierItemLimit`), episodes at 100x that (`EpisodeController.FreeTierLimitFactor`, generous on purpose, only to stop a raw-API caller flooding the database).
  Enforcement is API-side and two-layered: `[Authorize(Policy = "MemberOnly")]` on every restricted controller, plus the creation quota in `DataCrudControllerBase.Post` (403 with `{ error }`).
  `NavMenu.razor` hiding sections is UX, never security.
  `FreeTierTest` covers the quota and carries a reflection guard asserting each controller's expected policy.
- **Runtime-changeable global admin settings** live in one shared `app_setting` collection (single `_id: "global"` document, one field per setting) via `IAppSettingRepository`, which writes a targeted `$set` so unrelated settings are never clobbered.
  Reach for a new field here, not a new collection, and use `AppConfiguration`/env vars only for deploy-time values.

### Reference data (shared, owner-less)

`tvshow_reference`, `movie_reference`, `book_reference`, `videogame_reference`, `album_reference` and `person_reference` hold provider metadata.
They are the one deliberate exception to "every collection has `owner_id`": public facts about a real work, stored once, pointed at by every tenant's `ReferenceId`.
Matching key is normalized title plus year via `TitleNormalizer.Normalize` (shared with `TvTimeImportService` so the two never drift).

Providers: TMDB (TV/movie), IGDB / RAWG (video games), Discogs (albums), Google Books / Open Library / BnF (books), OMDb (IMDb ratings for TV/movie).

- These repositories do **not** extend `IDataRepository<TModel>`/`MongoDbRepositoryBase` (both are hard-constrained to `IHasIdAndOwnerId` plus owner-scoped paged CRUD).
  Write a small purpose-built repository for any new owner-less collection.
- `ReferenceEnrichmentService` is one `partial class` split by file (`.TvShowsAndMovies.cs`/`.Books.cs`/`.VideoGames.cs`/`.Albums.cs`), five methods per domain: `TryLinkExisting<X>ReferenceAsync`/`TryAutoResolve<X>Async`/`Resolve<X>Async`/`Refresh<X>ReferenceAsync`.
  Shared helpers (`TryLinkKnownReferenceAsync`, `ResolvePersonReferenceIdAsync`, `JoinGenres`) stay in the core file.
- It is the single place a title plus year resolves to a provider id, and it propagates the result to every tenant's matching document via `I<X>Repository.SetReferenceLinkAsync`.
  Automatic resolution fires from `<X>Controller.OnCreatedAsync` and from `TvTimeImportService`, both on their own DI scope and never awaited inline, since a bulk import must not block on a sequential chain of provider calls.
  The automatic path only acts on a **single, confident** result, zero or several candidates leaves the item for the admin queue rather than guessing.
- `SetReferenceLinkAsync` also sets `Title`, `Year` and, per domain, `Author`/`Artist`/`Genre`/`Language` from the canonical record: linking corrects what the tenant typed, it doesn't just attach an id.
  **Never overwrite with nothing:** a field the provider has no value for is left alone.
  `VideoGameModel.Platform`/`State` describe this tenant's own copy and are never overwritten.

#### Local aliases

**Every match path asks the local aliases before it asks a provider** (`TryLinkKnownReferenceAsync`, first thing in every `TryAutoResolve<X>Async`, and the whole of `TryLinkExisting<X>ReferenceAsync`).
A stored alias *is* the answer: someone already established that this title means that work, so re-deriving it through a fuzzy provider search is at best slower and at worst a different answer or none.
Propagation on a local hit reuses the same `Propagate<X>LinkAsync` a fresh resolve ends with.

`MatchedAliases` (`List<ReferenceMatchModel>`, tuple `(Title, Year, Creator, Isbn)`) records every combination ever confirmed to mean this work, both the canonical values and whatever the tenant searched with, merged and never overwritten.
Queries use `Builders.Filter.ElemMatch` so every condition must hold on the *same* array element (an `AnyEq`-per-field approach would match a title on one alias and a year on another), written once for all five collections in `Infrastructure.MongoDb/Repositories/ReferenceAliasQueries.cs` over the `IHasMatchedAliases` entity interface.

**An alias must carry its domain's whole identity or it is not stored at all** (`Domain/Services/ReferenceAliasRule.cs`, the single declaration, read by the enrichment merge and by each repository's canonical-alias safety net).
An alias is the local match key, so a half-key is not a weaker key: it answers questions it was never confirmed for.

- **Film, show, game: title plus year** (`TitleAndYear`), the same identity `ReferenceMatchRules` confirms with.
  No year, no alias.
- **Album: title plus creator, and deliberately no year** (`TitleAndCreator`).
  One release exists as many pressings under as many years, so the year narrows nothing the artist has not settled, while storing it minted one alias per year anyone typed.
  The lookup is a single `FindByTitleCreatorAsync`, there is no year-narrowed album lookup any more.
- **Book: title plus creator, with the year recorded whenever known** (`TitleAndCreatorWithYear`), or an ISBN on its own, which names one printing outright.
  Unlike an album, a book genuinely is republished as revisions the year tells apart, so an alias records the printing it was confirmed under.
  It is **recorded, not required**: requiring it would leave a book whose provider reports no year with no alias at all, and an item with no alias is not merely unmatched but *actively unlinked* the next time anyone presses "check for reference match", since finding nothing is what clears a link.
- The book lookup is a three-tier ladder, strongest key first (`FindKnownBookReferenceAsync`): ISBN, then `(title, creator, year)`, then `(title, creator)` whatever the year.
  That last tier is where most book matching actually lands, since a tenant's year routinely names an edition nobody confirmed, and it is the one tier that could guess and does not: `FindByTitleAsync` returns nothing when several references share a title and an author.
- `Creator` is always derived from the canonical provider response, never from tenant-typed text.
  TV, movie and game pass `null`.
- `Isbn` (Book only) is recorded only on the alias that actually used it: the canonical alias (provider-reported) and the tenant-search alias are separate entries, and the search alias's `Isbn` is never backfilled.
- Indexes follow each domain's lookup rather than one shape for all five: `title` plus `year` (tvshow/movie/videogame), `title` plus `creator` plus `year` (book, whose prefix also serves the year-agnostic tier), `title` plus `creator` (album), plus a partial `matched_aliases.isbn` index.
  An index that does not match the query leaves the `ElemMatch` scanning the collection.
- Aliases stored under the old rules are pruned by `scripts/prune-incomplete-matched-aliases.js` (dry run by default, `APPLY=1` to write), then re-run `scripts/mongodb-create-index.js`.

**The yearless title-only lookup refuses to choose: `FindByTitleAsync` returns the match only when there is exactly one** (`ReferenceAliasQueries.FindSingleMatchAsync`, read by the yearless title lookup for film/show/game and by the book `(title, creator)` tier).
It reads two documents and returns null for "none" *and* for "several", because **ambiguous and no-match are the same answer to a caller that must not guess**.
It was a plain `FirstOrDefaultAsync` over an unsorted unbounded match, so a yearless "Resident Evil 2" adopted whichever of IGDB's eight same-named games sorted first.
A single match still links, which is the ordinary case and the reason the fallback exists.
Deliberately **not** applied to `FindByTitleYearAsync` or to the album lookup: two documents sharing a domain's whole identity are a duplicate to merge, not an ambiguity to refuse.
Existing bad links are cleared by `scripts/unlink-yearless-ambiguous-reference-matches.js` (dry run by default, `APPLY=1` to write).

#### Resolution and confirmation

`Resolve<X>Async` checks for an existing reference document **by provider id first** (`FindByExternalIdAsync`), falling back to its domain's identity lookup (title plus year, or title plus creator for books and albums).
Title text alone can't prevent duplicates, since two tenants easily resolve the same entry through different strings, while the provider id is invariant and authoritative.

`*_tmdb_id` and external-id indexes are `unique: true` with `partialFilterExpression: { "external_ids.<key>": { $exists: true } }`.
The application check is what's *supposed* to prevent duplicates, the database constraint is what guarantees it.
The partial filter (not `sparse`, not a plain unique index) is required so documents missing the key don't all collide on one null.
**One index per provider that can write that collection**, not one per collection: a document legitimately holds ids from several, and each id space needs its own guarantee.
Books cover `googlebooks`/`openlibrary`/`bnf`, and `person_reference` covers `tmdb`/`discogs`/`googlebooks`/`openlibrary`/`bnf` (`ResolvePersonReferenceIdAsync` is handed the *linking* client's `ProviderKey`).

`TryLinkExisting<X>ReferenceAsync` is a second, cheaper path that never calls a provider: it only checks whether a matching document already exists.
It backs `POST /api/<collection>/{id}/refresh-reference`, the "check for reference match" control shown **unconditionally** on every detail page to **any** authenticated user, since it can only reuse a fact someone already established.
It deliberately does **not** short-circuit on an existing `ReferenceId`: `Title`/`Year` are freely editable, and replacing a bad match is the point.
On a match it updates this tenant's own document directly, then also calls `SetReferenceLinkAsync` with the pre-edit title and year so other unresolved tenants benefit.
On **no** match for an item that *was* linked, the link is cleared (`ReferenceId = ""`), which is exactly what returns it to the admin's unresolved queue.

**Gotcha:** the title-only fallback must run unconditionally, *including* when `Year` is null.
An earlier version skipped it unless `Year is not null`, which is backwards: `FindByTitleYearAsync(title, null)` can only match a reference whose own year is also null, so any linked item with no year unlinked itself the instant the button was clicked.

**Person dedup:** `person_reference` covers actors, book authors and album artists alike ("a named individual or group identified by a provider id"), deduplicated by provider person id via `ResolvePersonReferenceIdAsync`, never by name.
References store only the id, and `ReferenceDataController` hydrates names, `Cast` and `ProfileImageUrl` by joining server-side, which is why those DTO members are `[MapperIgnoreTarget]` rather than plain mapped members.

Images are **hotlinked from the provider CDN** (for example `https://image.tmdb.org/t/p/{size}{path}`, built once in the client and stored as a plain URL).
This is TMDB's sanctioned pattern, so there is no local storage or static-file subsystem to operate.

**Automatic resolution confirms a *named* match, it never trusts that a provider returned one row** (`ReferenceMatchRules`, shared by all five domains).
Counting rows reads a property of the *search* as a property of the *answer*, and it is wrong in both directions: it refuses ordinary titles (TMDB's search is fuzzy, `The Bear` + 2022 returns 8 results with the right answer first) and it links titles nobody compared (`search/tv?query=Fallout&first_air_date_year=2025` returns exactly one result and it is "Thirst Trap: The Fame. The Fantasy. The Fallout.").
A provider's own relevance is not the answer either: `Sinners` + 2024 ranks "In the Land of Saints and Sinners" first.

- **There are two identity shapes, and they are a real difference between domains rather than an inconsistency to flatten.**
  A film, a show and a game are a title **plus a year** (`ConfirmedMatches`): same-titled works are ordinary there, so the year is the only thing that separates them, and a single confirmed match links.
  A book and an album are a title **plus a creator** (`ConfirmedCreatorMatches`): Google Books answers `intitle:The Hobbit+inauthor:Tolkien` with 300 volumes spanning 1981 to 2012, all one book, so the year is a *tie-break inside the ranking and never a filter*, and several confirmed candidates are printings of one work rather than an ambiguity, so the best is linked instead of the set being refused.
- **An identity field is mandatory for any automatic link, in every domain** (owner's rule): a year for films, shows and games, a creator for books and albums.
  Without it the item waits for the detail page's "check for reference match", which escalates to the provider.
  The accepted trade is strictly fewer unattended links, and no wrong ones.
- **Candidates are not required to agree with *each other* about the creator, only with the one the tenant supplied.**
  Google Books credits one book to "J.R.R. Tolkien", "J. R. R. Tolkien" and "John Ronald Reuel Tolkien", so demanding they agree reads one author as three.
- **An exactly-spelled title beats a loosely-matched one** (`ConfirmedMatches`' two tiers).
  `NormalizeLoose` drops "the" and every parenthesised group, which is right when comparing one provider's canonical title to another's and wrong against tenant-typed text: TMDB answers `Alien` (1979) with both *Alien* and *The Alien*.
  Falling back to the loose tier only when nothing matches exactly is what still links `Shogun` to TMDB's *Shōgun*.
- **A hard year filter must never be the only query asked**, and which providers it applies to was measured one by one.
  TMDB TV's `first_air_date_year` **is** hard (`Severance` + 2021, `Squid Game` + 2020, `The Wire` + 2003 and `Adolescence` + 2024 each return zero), so `SearchTvShowAsync` asks with and without it and unions the two.
  Discogs' `year` is hard too.
  **TMDB's *movie* `year` is not** (`Road House` + 2024 still returns the 1989 film), so movies are ranked and never widened.

**Admin queue:** `ReferenceDataAdminController` (`AdminOnly`) handles manual search and link over a 5-way `ReferenceItemType`, using `ExternalId`/`Provider` (not TMDB-specific names) in its DTOs.

**A record update may never change a reference link, and the server enforces that rather than trusting the client** (`DataCrudControllerBase.PreserveServerOwnedFieldsAsync`, over the `IReferenceLinkedModel` the five reference-linked models implement).
A PUT is a full replace, so every field the client sends wins, and `OwnerId` was already overwritten from the caller's claims for exactly this reason.
The Blazor detail page sends the whole DTO on every field edit and holds a copy fetched the instant the page opened, which for a just-created item is *before* background resolution linked it, so the first edit wrote that stale empty link back over the real one.
**This was the root cause behind a long run of "it doesn't match, but if I click refresh it matches" reports** (`docs/findings/reference-matching.md`).
The link is still written freely by resolution, the detail page's check and an admin unlink, since those go straight through a repository rather than through the CRUD controller.

**Gotcha (`null` string filters, still relevant for old data):** "does this document have no reference link yet" cannot be `Eq(x => x.ReferenceId, null)`.
Documents written under the old AutoMapper stored `""` instead of BSON null and still exist.
Copy `TvShowRepository`/`MovieRepository`'s `UnresolvedFilter()` shape (null *or* empty) for any "is this string field unset" query.
It fails silently by matching zero documents, and only a real-MongoDB integration test catches this class of bug (`docs/findings/persistence-and-mapping.md`).

**Gotcha (null Find results):** every `Find*Async` that can legitimately return "nothing matched" must check `entity is null` **before** calling the mapper, because Mapperly throws on a null source.
This applies to `MongoDbRepositoryBase.FindOneAsync` too, which every `GetById` 404 check depends on.

**Data-shape renames need a migration script**, not just updated `[BsonElement]` attributes.
`PosterUrl` to `ImageUrl` silently blanked every pre-existing cover until `scripts/migrate-poster-url-to-image-url.js` (idempotent `$rename`).
By contrast `TvShowModel.Status` to `State` needed none, because the entity kept `[BsonElement("status")]`.
Run-once scripts follow that same idempotent style.

#### Per-provider findings (all confirmed against the real APIs)

**IGDB** is unlike every other client here in three ways, all handled outside the client so it stays an ordinary typed `HttpClient`.
It authenticates with a **Twitch app access token** rather than an api key: `IgdbTokenProvider` caches one per process (not in MongoDB, deliberately unlike `OmdbCallBudget`, because a token is not a shared *quota*) and `IgdbAuthenticationHandler` attaches `Client-ID` plus bearer, dropping the cached token and retrying **once** on a 401.
It documents **4 requests/second**, paced by a `TokenBucketRateLimiter` held in a singleton (`IgdbRateLimiter`) rather than on the handler, which `IHttpClientFactory` rebuilds on every rotation.
Queries are **POST bodies in Apicalypse**, not query strings, so a tenant-typed title is escaped before being embedded in a string literal.

- **Handler order is load-bearing: authentication, then resilience, then the rate limiter (outermost first).**
  The limiter goes *innermost* so its queue wait is covered by the resilience handler's total-request timeout, since these clients deliberately set `HttpClient.Timeout` to `InfiniteTimeSpan` and let the resilience pipeline own the bound.
  Its queue is bounded for the same reason, and overflowing is cheap because it sits inside: the 429 it synthesizes is retried with backoff, pacing a bulk pass instead of failing it.
- **The renewal margin is capped at half the token's lifetime.**
  A fixed margin longer than the lifetime puts the renewal point in the past the instant the token arrives, so every call fetches a new one.
- Missing credentials are a supported state (`IgdbSettings.IsConfigured`, same optional shape as `OmdbSettings`), every call short-circuits to an empty result.
- It reports **no Metacritic score**, and `aggregated_rating` is IGDB's own aggregation of external critic scores, which is why it gets its own `igdbcritic` key.
- **Gotcha: a stale field name fails silently.**
  `category` is gone from the API, and IGDB neither returns it nor complains about it, so `where category = 0` parses fine and matches **zero** documents.
  Its replacement is `game_type` (0 = main game).
  Field-level notes that don't shape the current code are in `docs/igdb-api-notes.md`.
- **Explore deliberately does *not* restrict to main games**, though `game_type = 0` would: a DLC or a remaster is a first-class thing to track here, so a well-reviewed expansion is a legitimate suggestion.
  The vote-count floor is the ranking's only filter.
- **`search` is relevance-ordered and genuinely noisy** ("Half-Life 2" returns three MMod variants above the canonical game), which is why admin search shows several candidates and automatic resolution only ever acts on a single one.
- `first_release_date` is unix **seconds**, `cover.image_id` builds `https://images.igdb.com/igdb/image/upload/t_cover_big/{image_id}.jpg`, and critic counts run an order of magnitude below user counts, which is why the two rankings have very different vote floors.

**Open Library** never sends `year` as a server-side filter: `first_publish_year` is the *work's* original year, not a tenant's edition, so filtering by it returns zero relevant results.
Year is still returned for display and tie-breaking.
It searches via `q=` (relevance across titles and alternates), not `title=` (field-scoped exact match), which misses regional variants entirely.
Its `first_publish_date` is routinely absent from the work JSON, so `GetBookDetailsAsync` falls back to a single-document `q=key:{workKey}` re-query.
Its `covers` array is contributed rather than curated, so an unattractive cover is expected.
It exposes **no** reliable series field, so `BookModel.Series` is deliberately not auto-filled.
Its `search.json` is also the slowest endpoint any provider here calls (36 to 41s, and 503s, measured during a real degradation), which is why its cross-provider **rating fallback is guarded**: `AddOpenLibraryRatingFallbackAsync` catches everything but `OperationCanceledException`, because an exception there used to escape `RefreshBookReferenceAsync`/`ResolveBookAsync` and discard a *complete* Google Books or BnF response.
Same rule as OMDb: an optional secondary provider may never fail the primary operation (`docs/findings/providers.md`).
Both callers pass the **previously stored** openlibrary rating in, so a lookup that never answered keeps what is known while a real "no rating" response clears it.

**An optional narrowing parameter must never silently zero out results a broader search would find.**
Discogs' `artist=` can fail to match its own indexing (disambiguation suffixes like `"Artist (2)"`), returning nothing for a title that succeeds alone.
Both `DiscogsClient` and `OpenLibraryClient` retry once without the author/artist parameter when the constrained search comes back empty.
Discogs' `year=` is the same trap and is no longer sent alone: `q=Kid A&artist=Radiohead&year=2001` returns exactly one master and it is *Amnesiac*, while the same query without the year finds the album at once, so `DiscogsClient` asks with and without it and unions the two.

**A provider's free-text parameter is not a title field, and `q=` results have to be re-checked.**
Discogs' `q=` matches the artist name, label, credits and tracklist too, which made albums *unlinkable* rather than just untidy, since `TryAutoResolveAlbumAsync` acts only on a single candidate.
`SearchAlbumsCoreAsync` discards any candidate whose **parsed** release title fails `TitleNormalizer.LooselyContains`, parsing the title out of Discogs' combined "Artist - Title" string first so an artist-only match is excluded.
Filtering rather than switching to the field-scoped `release_title=` is deliberate and measured: `release_title=` is precise but reorders badly (`Nevermind` plus Nirvana ranks the canonical 1991 album fourth).
The filter sits *inside* the core search, so "answered, but nothing was actually titled that" reaches the existing artist retry as the same state as an empty response.
Open Library's `q=` has the identical problem and is deliberately **not** filtered, since the book ladder is multi-provider and widens on empty.
That decision, and what it would take to revisit it, is in `docs/findings/by-design-and-gaps.md`: read it before "fixing" the noise.

**BnF**'s `"and (bib.author ...)"` CQL clause is not a strict intersection: title "La Peste" plus author "Victor Hugo" returned genuine Hugo anthologies instead of zero.
`BnfClient.SearchBooksCoreAsync` re-checks every candidate's parsed author client-side (`AuthorMatches`) and discards mismatches.
BnF is the one XML/SRU client (Dublin Core per `srw:record`), its `ExternalId` is the bare ARK, its `dc:creator` "LastName, FirstName (dates). Role" is normalized to "FirstName LastName", and its ordinary records carry **no** cover art at all.

**Google Books** is the book default (real synopses, covers, language, widest catalogue including manga).
It uses `intitle:`/`inauthor:`, and an `isbn` supersedes title and author entirely as the sole query, since an exact identifier must not be "and"-ed with a fuzzy match.
**Its `volumes?q=` search endpoint went fully 503 for days in August 2026 while `volumes/{id}` kept answering 200**, so don't diagnose a "book search is broken" report from the app's error text alone, curl the endpoint.
`CleanDescription` keeps the documented `b`/`i`/`br` HTML rather than flattening it: it decodes entities **first** (so an entity-encoded tag can't re-materialize), converts real newlines to `<br/>` **before** the allowlist pass, then reconstructs those three tags bare and strips everything else including attributes.
That fixed allowlist-and-reconstruct (not a general sanitizer) is what makes `BookDetail.razor`'s `MarkupString` render safe, so **never render a `MarkupString` from text that hasn't been through it.**
It also upgrades `imageLinks.thumbnail` to `https://` to avoid mixed-content blocking.

#### Shared search policies

**The book search policy is written once in `BookReferenceClientBase`**, not per provider: try the ISBN alone, then title plus author, then title alone, widening only when a step returns **empty**.
A provider supplies just its two query shapes (`SearchByIsbnAsync`/`SearchByTitleAsync`).
**An ISBN miss widens rather than short-circuiting**, since a catalogue that doesn't index an edition must never make supplying an ISBN *worse* than leaving it blank.
No book provider sends `year` as a server-side filter, each for its own confirmed reason, so the shared primitives don't take one.

**Books are the one domain behind a provider-agnostic interface** (`IBookReferenceClient` with `ProviderKey`/`DisplayName`) and the one with several providers registered at once.
`Program.cs` registers all of them (typed `AddHttpClient<TConcrete>` bridged via `AddTransient<IBookReferenceClient>`, transient so `IHttpClientFactory`'s handler rotation isn't defeated), and registration order is the admin picker's display order.
`BookReferenceClientRegistry` resolves a key (or the `ReferenceData:BookProvider` default, matched case-insensitively) to a client, so the provider is a per-request admin choice rather than a deploy-wide switch.
`RefreshBookReferenceAsync` checks **every registered** provider's key against `ExternalIds`, not just the default's, otherwise a reference linked through another provider silently stops refreshing forever.
`ReferenceEnrichmentService.Books.cs` never hardcodes a provider name, so a new provider needs only its own class plus one registration block.
Admin provider buttons are selection-only, search is triggered by exactly one control.

**The video game search policy is written once in `VideoGameReferenceClientBase`**, the same split: a client supplies only `SearchByRelevanceAsync(title, limit)` plus its other query shapes, and `SearchGamesAsync` asks `FindGamesByExactTitleAsync` **first**, unions the relevance pool, and ranks what came back.
A provider's relevance ranking is not an answer on its own and truncating it to what gets displayed is what loses the game: `search "Code Vein"` puts the 2019 game sixth behind its own sequel, three DLC packs and a season pass.
So the exact-name lookup guarantees a perfect title match is always among the candidates, the relevance query reads `RelevancePoolSize` (50) to fill a five-slot picker, and the ranking chooses.

**`ReferenceMatchRules` is the single declaration of "is this candidate that work", read by every surface in every domain that answers it**: the search ranking, `TryAutoResolveVideoGameAsync`'s confidence check, and `TryAdoptDefaultVideoGameProviderAsync`/the admin reconciliation row.

- `OrderByBestMatch` orders every candidate list a human sees: names the work (`TitleNormalizer.LooselyEqual`), then the year, then title distance (an edition, DLC or bundle is the game plus something, so the shortest is closest to what was asked for), then title for a total order.
  The provider's own relevance is deliberately not a key.
- `YearRank` is **three-state, not a boolean**: the requested year, then a candidate the provider reports **no** year for, then a contradicting year.
  Folding "unknown" into "contradicts" discards the right answer when a provider has no date, folding it into "agrees" counts it as confirmation.
- `ConfirmedMatches` returns **only the best year tier any candidate reaches**, which is what makes the year decisive rather than decorative: a search for "Resident Evil 2" (2019) finds the 2019 game and an undated namesake, and reporting both as an ambiguity would strand it forever.
  A contradicting year never confirms however alone the candidate is, since that is precisely where a title match is a remake or a same-named sequel.

**`TryAutoResolveVideoGameAsync` links on a single *confirmed* match, not on "the provider returned exactly one result".**
The old rule linked whatever came back when a query happened to be narrow and refused every title with namesakes however unambiguous the year made it: IGDB holds eight games named exactly "Resident Evil 2", three of them 1998, so that year stays a human decision.

**A year is required for any automatic video game link** (owner's rule): `TryAutoResolveVideoGameAsync` returns immediately when `year is null`, and this domain alone has **no** title-only local fallback in `TryLinkExistingVideoGameReferenceAsync`.

**The detail page's "check for reference match" escalates to the provider when nothing local matches** (`LinkVideoGameReferenceAsync`, and now `LinkTvShowReferenceAsync`/`LinkMovieReferenceAsync`/`LinkBookReferenceAsync`/`LinkAlbumReferenceAsync`).
Without it the identity field is a one-shot chance taken at creation: an item created before its year was known writes no reference at all, so the local-only lookup has nothing to find however correct the title and year later become.
It adds no guessing, since it links exactly what resolution on create would have.
**Editing a field never searches by itself**, there is no update hook and the button is the only thing that re-resolves.

The journey is covered by `VideoGameReferenceMatchSmokeTest` (three Playwright scenarios, real UI through real IGDB), because every regression here got past a green unit suite.
**Those tests only mean anything while no reference is left behind**, so they delete every one they create (`End2EndFixture.RemoveVideoGameReferencesAsync`), otherwise the local lookup answers and they pass with the provider escalation disabled.
**A lower unattended-link rate here is the design, not a regression** (owner's call), so when matching looks too strict, improve the *queries* (ask more ways, read a deeper pool, rank better) rather than loosening what counts as identity.
Every regression this domain has had is written up in `docs/findings/video-game-matching.md`.

**No video game client sends the year as a server-side filter**, though Apicalypse accepts it: that is the "an optional narrowing parameter must never silently zero out results" trap, and RAWG's `&dates=` was a real instance of it.
Being wrong about a year costs a place in the list, never the result.

#### Video game providers and reconciliation

**Video games are the second multi-provider domain** (`IVideoGameReferenceClient`, `ReferenceData:VideoGameProvider`), added when RAWG went down: `IgdbClient` (`igdb`, the default) and `RawgClient` (`rawg`).
The registry is shared: `ReferenceClientRegistry<TClient>` over `IReferenceProviderClient`, one class for both domains.

**Only the default provider is ever called on refresh**, the one deliberate divergence from `RefreshBookReferenceAsync`'s "refresh through whichever provider linked it".
That rule is right for books, where every registered provider is reachable, but this domain gained a second provider *because the first went down*, so falling back would make every not-yet-adopted reference pay a full retry-and-timeout cycle against a dead host on every pass.
A reference that can't be adopted keeps the data and provider ids it has, and is stamped as checked so the staleness queue rotates past it.
RAWG stays registered so an admin can still search and link with it, and so its stored `rawg`/`metacritic` values keep rendering.

**A reference linked before the default changed adopts the new provider's id during the sync** (`TryAdoptDefaultVideoGameProviderAsync`), which carries a catalogue across a provider change with no migration script.
The match rule is stricter than ordinary auto-resolution (exactly one candidate whose title matches the reference's, with a compatible year) because a reference's title and year is canonical provider data, not tenant-typed text.

- **Adoption failing is not a cosmetic backlog: it silently breaks Explore.**
  The exclusion asks each linked reference for the *discovery* provider's id, so a reference still in the previous provider's id space is a game the owner tracks and keeps being suggested anyway (105 of 344 references stuck, on real data).
- **How it asks matters as much as how it compares.**
  `FindAdoptionCandidatesAsync` runs a ladder: `FindGamesByExactTitleAsync` (IGDB's `where name ~ "..."`, a case-insensitive equality), then the same two queries with `TitleNormalizer.StripDisambiguator` applied, since RAWG puts a remake's original year in the title (`GoldenEye 007 (1997)`) and IGDB answers nothing at all to such a string.
- **It widens on "nothing *matched*", not on "nothing came back", and accumulates candidates across every rung.**
  A provider's relevance search hands out an unrelated non-empty answer at least as readily as an empty one (IGDB answers `NieR:Automata` with a single "Untitled NieR:Automata Project"), so stopping at the first non-empty reply meant the rung that would have found the game was never asked.
- **A provider's search is far more punctuation-sensitive than its catalogue**, so the ladder also asks with `TitleNormalizer.ToProviderQuery` (accents folded, apostrophes dropped, every other non-alphanumeric run collapsed to a space, keeping casing and every word unlike `NormalizeLoose`).
  `search "NieR:Automata"` never returns the game while `search "NieR Automata"` returns it first.
  Last, and only while nothing has matched, the folded form is retried with trailing words dropped (`MaxTruncatedQueries` = 3, never below `MinTruncatedQueryWords` = 2, both measured).
- **The last rung is every word as a substring** (`FindGamesContainingAllWordsAsync`, IGDB's `name ~ *"marvel"* & name ~ *"avengers"*`), the only shape that survives the provider spelling a title with punctuation the reference omits.
  It is unranked by construction, so its hits are shortlisted to the eight closest to the title asked for (`ShortlistByClosestTitle`, on `NormalizeLoose` length), and a genuine match is distance zero and can never be cut.
  RAWG has no substring operator and emulates it over one `search=` page.
- **`Marvel's Avengers` still isn't adopted unattended, on purpose**: one apostrophe apart from `Marvel Avengers`, and a rule equating those would equally equate `The Sim` with `The Sims`.
  A queue entry is one click, a wrong link is silent data loss.
- Confirmation is always against the **reference's** own title, never against whichever query found the candidate, which keeps a widened or admin-typed query from confirming something the strict rule would refuse.
  It uses `TitleNormalizer.NormalizeLoose`, not exact normalized equality, which rejected `Mass Effect: Legendary Edition` against IGDB's `Mass Effect Legendary Edition`.
  Loosening the *shortlist* is safe because nothing else loosens: the year must still agree and a single match is still required.
  `Normalize` stays strict, since it keys stored aliases matched against tenant-typed text.
- A fruitless attempt is stamped on the document (`ProviderAdoptionCheckedAt`, per provider, `ProviderAdoptionReattemptAfter` = 7 days), the same "remember what was already asked" rule as `RatingsCheckedAt`.
  The admin reconciliation action ignores the window, since someone is waiting on the answer.

**Admin provider reconciliation** (`GET/POST /api/reference-data/provider-reconciliation*`, `AdminOnly`, video games only) is where what adoption refuses to guess gets resolved, plus the duplicates a provider change leaves behind.
Video-game-only on purpose: this is the one domain refreshed exclusively through the default provider, which is what makes "carries no id in that provider's space" a self-inflicting gap.

- The gap list and duplicate groups are plain database reads (`FindWithoutExternalIdAsync`, using `Exists(..., false)` since a missing key is not a null one), and **candidates are fetched per row on demand** because each row costs a provider call or two and the queue routinely runs to three figures.
- **A row can be searched with the admin's own text, or by pasting the game's provider page URL** (`?query=` on the candidates endpoint), because a provider's search has genuine dead ends no automatic rung can clear.
  A URL or a bare numeric id resolves through `IVideoGameReferenceClient.FindGameByIdentifierAsync`, and `ProviderWebLinks.TryReadIdentifier` deliberately treats **nothing else** as an address: a hyphenated word like `Half-Life` is an ordinary thing to search for and looks exactly like a slug.
  Candidates are still confirmed against the reference, so typed text widens what is *found*, never what counts as an automatic match.
- `AdoptVideoGameProviderIdAsync` writes the picked id onto the **existing** document and then reuses `RefreshVideoGameReferenceAsync`, deliberately not going through `ResolveVideoGameAsync` whose title-based lookup could mint a second document.
  It refuses outright when another document already claims that id, naming it, so "it didn't work" becomes "merge these two".
- `MergeVideoGameReferencesAsync` fills the survivor's gaps and never overwrites it, **re-points every tenant's item** via `IVideoGameRepository.RepointReferenceAsync`, then deletes the absorbed document (absorbed first, since while both exist they hold ids the unique partial indexes will not let two documents share).
  Skipping the re-point would blank those items' cover, rating and Explore exclusion without a word.
- **The cover is the one field the survivor does not automatically win**: `MergedImageUrl` applies the same rule as `PreferredImageUrl`, so a RAWG-linked document's key art survives whichever document the admin keeps.
  A RAWG URL cannot be recomputed from its id without RAWG's API, so keeping the survivor's would be permanent loss for a cosmetic downgrade.
  **It is computed before the ids are unioned, and that order is load-bearing**: the "is this a RAWG image" test is "does this document carry a rawg id", which is exact only while the two documents are still separate.

**A stored cover on a RAWG-linked reference is never overwritten by another provider** (`PreferredImageUrl`, applied by both `ResolveVideoGameAsync` and `RefreshVideoGameReferenceAsync`).
RAWG's `background_image` is curated landscape key art and its image CDN still serves those URLs even though its API doesn't, while IGDB's portrait box art is a downgrade, its artwork is contributed, and its screenshots are raw frames with HUD.
**RAWG itself is exempt from that guard, and that half is load-bearing.**
The rule keys on "this document carries a rawg id", which is only a proxy for "the stored image is a RAWG image", and the two diverge as soon as a document holds both ids.
Without the exemption, re-linking through RAWG added the rawg id and then discarded the key art it had just fetched in favour of the stored IGDB cover.

**A provider may only overwrite its own sources' ratings** (`MergeProviderRatings`, keyed on `IVideoGameReferenceClient.SupportedRatingSources`).
An IGDB refresh must leave a reference's `rawg`/`metacritic` values alone, since they are still rendered and re-earning them would cost a call to a provider that may be down.
A source the provider *does* own but no longer reports is correctly dropped, since that's an answer rather than an absence.
Unlike books, the video game details record carries the `Ratings` map *built by the client*, because each provider has two scores on scales that differ per provider.

TV, movie and album stay hard-wired to TMDB and Discogs (provider-named DTOs and `ExternalIds` keys on purpose, swapping one would be a redesign rather than config).

#### Ratings

Two classes, deliberately split.
`RatingSourceCatalog` is the *declaration table*: every source key any stored value can carry, its scale, and `RatingReattemptAfter` (90 days).
**A source key is not a provider**, so `rawg` and `metacritic` stay declared long after RAWG stopped being the default, since `ScaleOf` throws on an unknown source and references linked through RAWG still display those values.
`RatingSourceOptions` (injected, like `ExploreRankings`) answers the *deployment* question: which sources a domain currently offers an admin, and which is effective.

- **The video game answer is read from whichever client is registered as that domain's default** (`SupportedRatingSources`), never from a list in the code, so `ReferenceData:VideoGameProvider=rawg` brings `rawg`/`metacritic` back with no code change and no migration.
  A hardcoded list got this wrong in both directions: it offered Metacritic long after IGDB became the default although IGDB cannot produce it, so every game linked since resolved to no rating at all while `MergeProviderRatings` kept older RAWG-era values showing and hid the breakage.
- **A stored override that isn't currently on offer is ignored, never erased**, which is what makes a provider change reversible.
- Movies and TV stay a fixed pair (TMDB vs IMDb) because IMDb is not a second provider for that domain, it's an extra per-title lookup layered on TMDB's own data.
- The admin card, `rating-sources` GET/PUT and `.../recompute` are all domain-generic over `RatingSourceCatalog.SelectableDomains`, so a domain gaining a second source needs only a catalog entry.
  The picker is a `form-select` dropdown, not a button row, since buttons render at different widths by text length.
- **A tenant item's denormalized rating carries the source it came from** (`ReferenceRatingSource`, on all five models, entities and DTOs), alongside `ReferenceRating`/`ReferenceRatingScale`.
  Everything that writes the value writes the source: `SetReferenceLinkAsync`, `SetReferenceRatingAsync`, the `TryLinkExisting*` direct updates, and the clear-on-unlink branches (which clear all three).
  The source is stamped **even when that source has no value for the reference**, since it records which source the copy was computed from rather than where a number came from.
- **`recompute` does nothing when there is nothing to do:** it opens with `CountLinkedOnOtherRatingSourceAsync` and returns `(0, 0)` without reading the reference collection at all when no linked item is on another source.
  An item stamped with nothing (linked before the field existed) counts as mismatched, so the first recompute backfills it and no migration script is needed.
  It is deliberately **not** a value-drift repair, which is the periodic sync's job.
- **When it does have work, a batch is one projected read and one bulk write** (`RecomputeBatchSize` = 500, sizing both): `I<X>ReferenceRepository.FindRatingsAsync(afterId, limit)` projects `_id` plus `ratings` and pages by an `_id` cursor, and `I<X>Repository.SetReferenceRatingsAsync` writes the page back as a single unordered `BulkWrite` of `UpdateMany` entries.
  The tenant items are still re-stamped server-side inside each entry, so more users mean more documents written per reference, never more round trips or more memory in the API.
  The five identical propagation bodies live once in `Infrastructure.MongoDb/Repositories/ReferenceRatingQueries.cs` over the `IHasReferenceRating` entity interface.
- Books are the one domain with no selectable source: `BookPrimaryRating` reads whichever provider key the reference happens to store, and a reference with no rating has no source to name, which is why the source is nullable end-to-end.

**OMDb** supplies IMDb ratings, keyed by the IMDb id TMDB exposes (IMDb has no public ratings API), native on `/movie/{id}` and appended via `?append_to_response=external_ids` for TV.
It is optional and best-effort: `OmdbSettings.ApiKey` is nullable and a missing section coalesces to empty, so a deployment without a key just keeps TMDB ratings.

- **OMDb's free tier is a hard 1000 calls/day, so every OMDb call goes through `OmdbCallBudget`.**
  The count is one shared MongoDB document per (provider, UTC day) (`provider_quota`, `_id` = `"omdb:2026-08-03"`, TTL 7 days) reserved with the same atomic filtered upsert `LeaseRepository` uses, because an in-process counter would let every replica spend the whole allowance.
  Reservation happens **before** the HTTP call, so an over-count is possible and an under-count is not, the safe direction against a hard limit.
  `Omdb:DailyCallBudget` (1000) and `Omdb:InteractiveReserve` (50) are the only knobs: `OmdbCallPriority.Interactive` may reach the whole allowance, `Background` stops short of the reserve, so a heavy batch day can never make a user's action come back unrated.
- **`OmdbClient` never throws for anything OMDb or the network can do**: an unknown id, an unrated title, a spent quota, a timeout, a 5xx and an open circuit all come back as an `OmdbLookupResult`.
  It used to call `GetFromJsonAsync`, which throws on the **401** an exhausted key answers with, surfacing as a 500 from admin manual linking and from Explore "add".
  Both of OMDb's 401s (`"Request limit reached!"` and a rejected key) write the day off via `OmdbCallBudget.MarkLimitReachedAsync`.
- **`OmdbLookupResult.Attempted` is the load-bearing half of that result.**
  "OMDb answered and has nothing for this title" may be recorded, "we never got to ask" must leave **no** stamp, or one exhausted afternoon writes those titles off for the whole re-attempt window.
- **A backfill the spent quota skipped must not stamp `LastEnrichedAt` either** (`ImdbBackfillOutcome.Deferred`, returned by `BackfillImdbRatingAsync` and honoured by both no-change short-circuits).
  Stamping a document the pass admittedly did nothing for drops it out of `FindStaleAsync` for the whole 3-day window, so a quota-capped day converges in 3-day steps instead of daily.
  This is the one exception to "always stamp so the queue keeps moving", and only because it is narrow and self-limiting: only a spent allowance defers (checked before the call and re-read after it), and the allowance renews at UTC midnight.
  A missing key or a failed request deliberately still stamps, since neither can be retried into working.
- **Gotcha:** the `/changes` short-circuit (`LastEnrichedAt is not null && Ratings.Count > 0`) means a reference enriched before IMDb existed would never backfill one.
  `BackfillImdbRatingAsync` resolves the id cheaply on the no-change path via `/{tv,movie}/{id}/external_ids` (one call, no season fan-out), stores it, then does one OMDb call, which is self-correcting once the id is stored.
- **A title IMDb has nothing for is remembered, not re-asked every pass.**
  TV and movie reference documents carry `RatingsCheckedAt` (`ratings_checked_at`, source to last attempt), the same map and window as the Explore catalogue's.
  `BackfillImdbRatingAsync` checks the window **before** the id lookup so both calls are skipped, a re-resolve carries the existing stamps over rather than restarting them, and the Interactive paths ignore the window entirely.
  No index and no migration: unlike Explore's map this is never a query filter, and a missing field deserializes to "never attempted".
- **Gotcha:** a full fetch rebuilds `Ratings` from TMDB, and the imdb value doesn't come from TMDB.
  `RebuildRatingsAsync` (shared by both full-fetch paths) keeps the known value when the call never happened, while "OMDb answered and has nothing" is a real answer and does clear it.

#### Export and import

`GET/POST /api/reference-data/export`/`import` round-trip all six reference collections as a zip of JSON arrays, so reference data is portable across environments instead of re-earned per deployment.
`FindAllAsync()` exists solely to back the export (unpaged, acceptable because this data is small and shared), and the export is a straight serialization of the models so Mapperly's unmapped-member errors keep it field-complete.

**The import is a background job** (202 plus job id, `GET /api/reference-data/import/{jobId}` to poll), not a blocking request: a real export is tens of thousands of documents written one at a time, so as a blocking call it reliably outlived the client's default 100s `HttpClient.Timeout`.
The upload is buffered on both sides for the same reason (a Blazor `IBrowserFile` stream handed to `StreamContent` makes the browser feed the file down the SignalR circuit *during* the POST).

**The import matches every document by its provider id, never by the `_id` it was exported with** (`Domain/Services/ReferenceDataImportService.cs`, one generic algorithm over all six collections, taking `FindAllAsync`/`UpsertAsync` as delegates since the repositories share no base interface).
An `_id` is local to the database that minted it, so upserting by it meant the same real work landed as a second document in any environment that had already resolved it, which the unique partial indexes reject outright.
Matching on the provider id keeps the **target's** `_id`, which is what every tenant's `ReferenceId` and every `Cast[].PersonReferenceId` points at.
Matching walks whatever keys a document carries, so no provider is named anywhere in the algorithm, and an `_id` match survives only as the fallback for a document with no provider id at all.

- **People are imported first, and every document citing them is re-pointed** at the id the target stores them under (`Cast[].PersonReferenceId`, `AuthorReferenceId`, `ArtistReferenceId`).
  Otherwise imported cast rows point at ids that don't exist in the target, a silent break since a missing person just renders as no cast.
- **A match merges, it doesn't replace.**
  The target legitimately knows things the export doesn't: `MatchedAliases` its own tenants confirmed, and `Ratings` from a provider the exporting environment never called.
  Accumulated fields are unioned (`RatingsCheckedAt` keeps the *later* attempt per source), and anything the import has no value for leaves the target's alone.
- **A provider id another document already claims is left behind and reported** (`SkippedExternalIds`, surfaced in the admin UI and logged) rather than written and taking the whole import down with it.
- **Matching by provider id has one gap, and it is reported rather than closed** (`PossibleDuplicates`): an export whose games are IGDB-linked lands *beside* a target's RAWG-linked copies of the same games, since the two share no id.
  Deliberately not auto-merged, because title text is not identity and an import fusing two unrelated records is the one outcome nothing downstream could undo.
- Covered by `ReferenceDataImportResourceTest` over real HTTP and real MongoDB, per domain and per provider, since the failure mode being prevented *is* the unique index firing.

### Keeping reference data fresh: periodic and on-demand sync

`ReferenceSyncBackgroundService` is a plain in-process `BackgroundService` on a 24h `PeriodicTimer` (with an immediate pass at startup), deliberately **not** a Kubernetes CronJob, since a second scheduled workload is real operational overhead for a job this cheap.
Every replica runs the loop but only one syncs per cycle: each tick tries `ILeaseRepository.TryAcquireAsync("reference-sync", Environment.MachineName, 1h)`, an atomic filtered upsert whose mutual exclusion is the `lease` collection's `_id` uniqueness (covered by the real-Mongo `LeaseRepositoryTest`).
A replica dying while holding the lease delays the next pass by at most 1h against a 24h cadence.

`ReferenceSyncService.SyncStaleReferencesAsync(staleAfter, ...)` is the single sync algorithm, shared by the loop and the admin's `POST /api/reference-data/sync-now`.
**The two callers differ in nothing but the staleness windows, and those are declared once in `ReferenceSyncWindows`** (`Periodic` = 3 days for references and 7 days for Explore, `Forced` = `TimeSpan.Zero` for both).
`sync-now?force=true` re-checks everything, and without `force` it runs exactly what the background tick would have taken, which is why an admin run right after a forced one legitimately reports zero checked.
Restating either window at the second call site is what would let them drift apart, so `ReferenceSyncBackgroundService` reads `ReferenceSyncWindows.Periodic` rather than holding its own constants (`ReferenceSyncWindowsTest` guards it).
One failing document never aborts the run, each is caught and logged individually.
It is **one** generic loop over five one-line domain arms (`SyncDomainAsync`), the same shape as `RecomputeReferenceRatingsAsync`.

**Which documents a pass takes, and in what order, is `I<X>ReferenceRepository.FindStaleAsync(cutoff, limit)`**: a server-side filter and sort (shared once in `Infrastructure.MongoDb/Repositories/ReferenceStalenessQueries.cs`), replacing a `FindAllAsync()` that read every reference document into memory each tick.
Never-enriched first, then least-recently-enriched, capped at `MaxDocumentsPerDomainPerPass` (500).
The order is what makes the cap safe: a pass always takes the stalest end, so whatever it doesn't reach leads the next one.

**Gotcha:** "never enriched" cannot come from the date comparison.
MongoDB compares within a type, so `Lte(LastEnrichedAt, cutoff)` matches neither a null nor a missing field, and the documents most in need of a pass would be exactly the ones the query could never return.
`Eq(field, null)` matches both null and missing, and ascending order then puts them first for free since BSON sorts null ahead of every date.
Only the real-Mongo `ReferenceStalenessRepositoryTest` catches this, and `last_enriched_at` is indexed on all five reference collections for the query.

`RefreshTvShowReferenceAsync`/`RefreshMovieReferenceAsync` lead with a cheap pre-check: TMDB's per-id `/changes?start_date=...` (one call, no season fan-out).
If nothing changed, only `LastEnrichedAt` is bumped and the full details plus per-season cast calls are skipped, and a reference with no `LastEnrichedAt` always does the full fetch.
**Divergence:** IGDB, RAWG, Discogs and the book providers expose no `/changes` equivalent, so those domains always full-fetch once past the staleness cutoff, and their `*Updated` counts always equal their `*Checked` counts.

**Gotcha:** the service is registered unconditionally but only works when `Features:IsReferenceSyncEnabled` (default `true`), checked fresh every tick.
`KestrelWebAppFactory` overrides it to `false` via `ConfigureAppConfiguration` (in-memory source added last, so it wins), and `UseSetting` was tried and silently doesn't work for a top-level-statement minimal-hosting `Program.cs`.
Without the override, every integration fixture fired real TMDB calls.
**Use `KestrelWebAppFactory<Program>` for any new integration fixture**, even one that doesn't need real Kestrel networking, so it inherits this for free.

### TV Time import

`POST /api/import/tv-time` (background job, see "Long-running work").
Findings, all confirmed against real export data:

- `seen_episode_source.csv` alone is a drastically incomplete episode history (only written from TV Time's episode-detail screen), so `TvTimeImportService` also reads `tracking-prod-records.csv` and `-v2.csv`, merged and deduplicated per (show, season, episode), earliest date wins.
- `followed_tv_show.csv` is not a complete show list either (confirmed with "The Pitt"), so `ImportEpisodesAsync` creates shows on the fly from watch events.
  Don't reintroduce a "skip if not already followed" check.
- Movies **do** have watch dates: `tracking-prod-records.csv` carries `entity_type == "movie"` rows with `type` watch (`FirstSeenAt`), towatch (`WantToWatch`, only when there's no watch event) and follow.
  `-v2.csv` carries no movie data.
  If a field looks suspiciously absent, re-check the real export before documenting it as a limitation.
- **Idempotency is by stable id, never by title.**
  Enrichment rewrites `Title` to the canonical name after the first import, so title matching duplicated everything on re-import.
  Every imported show or movie is stamped with `TvTimeId` (`IHasTvTimeId`, carried through entity and DTO and round-tripped on edits since `UpdateAsync` is a full replace): TV Time's show id, or the per-movie tracking `uuid`.
  When the export carries no id, `ResolveTvTimeId` synthesizes a deterministic `tvtime_title:<normalized-title>` from the **export** title (which enrichment never touches), and `BuildIdByTitle` maps titles to ids across the id-bearing files first so title-only files resolve to the same id.
- `UpsertIndex<TModel>` matches by `TvTimeId` first, and a title fallback fires only for a pre-existing record with no id yet, which is adopted and back-filled once (`BackfillTvTimeIdAsync`).
  A record carrying a *different* id is left alone.
- **On a match the record is left untouched**, since a re-import must never clobber edits made in the app afterwards (rating, notes, favorite, corrected title or year).
  Only new items are created, and counts are deduped by reference identity.
- **Gotcha:** a CSV property present in only some of the three files' headers (for example `TvShowId`) needs `[Optional]` from `CsvHelper.Configuration.Attributes` on top of not being C# `required`, because CsvHelper's header validation throws regardless of nullability.

### Watch Next

`WatchNextService.ComputeInProgressShows(shows, episodes, referencesByShowId)` reports a show only if its `State` is `TvShowStatus.Current` **and** the linked reference's episode list has an entry after the last one watched, compared by `(SeasonNumber, EpisodeNumber)` and never by title or air-date order, whose `AirDate` has already passed or is unset.
A show with no `ReferenceId` or no reference document is excluded rather than guessed at.
The controller only fetches reference documents for shows that are `Current` and linked.
The DTO reports the confirmed next episode (`InProgressShowDto.Next*`), which is real episode-guide data rather than the old "+1" heuristic.

`FilterMoviesToWatch` excludes a movie once `FirstSeenAt` is set even if `WantToWatch` is still true, since the flag can go stale, so the exclusion happens at read time.

**`WantToWatch` is movie-only, TV shows deliberately don't have it.**
The flag once existed on `TvShowModel` with no consuming feature and was removed everywhere (plus `scripts/unset-tvshow-want-to-watch.js`).
If a "shows I want to start" surface is ever wanted, build a real Watch Next section rather than a dead flag.

`TvShowDetail.razor`'s episode checklist applies the same `AirDate is null || AirDate <= today` filter before grouping into seasons, so an announced-but-unaired season simply doesn't appear.
It's a full watch-through checklist once the show has a `ReferenceId` (checking a box creates an `Episode` with `WatchedAt = today`, unchecking deletes it), falling back to the recorded-episodes-only view with a manual add form when it doesn't, a deliberate scope boundary since episode counts are unknowable without reference data.

### Explore (discovery)

`ExploreController`/`ExploreService` (`/explore`) suggests top-rated titles the caller doesn't track, with one-click add and dismiss/undo.
Movie, TvShow and VideoGame only, Book and Album 400 (no best-of listing to read).

- **The discovery list originates from the provider, never from local `*_reference` collections.**
  That was the original implementation's core mistake: a reference document only exists because someone already tracks that title, so a local query can only re-suggest what's already owned.
  Sources: TMDB `/{movie,tv}/top_rated`, and the video game provider's own ranked query (IGDB `sort {rating|aggregated_rating} desc`).
- **The read path doesn't call the provider: it pages `explore_catalogue`, a materialized copy of each ranking** written weekly by `ExploreCatalogueRefreshService`.
  The ranking is a *global* fact (every user's page is the same list, only the exclusions differ), so fetching it per request was duplicated work and the few pages a request could afford is what once capped Explore at roughly the top 100 titles.
  Owner-less like the `*_reference` collections, for the same reason.
  `CatalogueDepth` (1000 per ranking) is the "how far can you scroll" knob and costs one provider call per page of depth per week, nothing per request.
- A **ranking** is a domain plus an *ordering*, not a domain plus a displayed rating, and `ExploreRankings` is the single declaration, derived from `RatingSourceCatalog` so a new source needs no second list.
  TMDB publishes one top-rated list whatever the rating source is, so movies and TV have one ranking each, while a game provider genuinely sorts differently per source so video games get one ranking per source its active provider supports.
  **`ExploreRankings` is an injected service, not a static class**, precisely because the video game answers come from whichever provider that deployment registered as the default.
  `DisplaySource` is the other half: a source the catalogue cannot carry falls back to the ranking's own number rather than blanking every card.
  A pass also prunes entries whose `(type, ranking)` is no longer maintained at all, since `DeleteStaleAsync` only prunes *within* a ranking it just rewrote.
- Ordering follows the admin-selected primary rating source (`RatingSourceCatalog.Resolve`, no Explore-specific setting), which now selects which stored ordering to read.
  Movies and TV under **IMDb** are the awkward case (IMDb has no catalogue API): the entries stay in TMDB's order and IMDb only fills in the displayed number, deliberately not re-sorted by it since partial IMDb coverage would float unrated titles to the top.
  That number is backfilled by the refresh pass (each entry costs a TMDB plus an OMDb call, spent from the shared `OmdbCallBudget`, sized to whatever the reference sync left of the day's allowance), so an entry deep in the ranking can legitimately have no IMDb rating yet.
  Attempts are stamped whenever OMDb actually answered, whether or not it produced a value, and a call the budget refused is not stamped and simply retries next pass.
  `app_setting.explore_use_tmdb` forces movies and TV back onto TMDB's vote and skips the backfill entirely, read only when IMDb won the resolve so it can't leak into the game domain.
- **A suggestion card links out to the title's provider page, in a new tab** (`ExploreSuggestionDto.ProviderUrl`/`ProviderName`, the whole card or row being the link), the one "read more" a suggestion can offer since it is by definition not in the collection yet.
  It follows the *displayed* rating source where possible and falls back to the discovery provider.
  URLs are **stored per source** on the entry (`web_urls`, merged key-by-key exactly like `ratings`), not derived at read time, because IGDB and RAWG key their pages on a *slug* so those come back from the listing itself.
  `ProviderWebLinks` holds only the ones an id does determine (TMDB's `/movie/{id}` vs `/tv/{id}`, IMDb's `/title/{ttId}/`).
  The IMDb link is a free by-product of the rating backfill and is **stored even when the OMDb call never happened**, since withholding a fact already in hand would leave the card linking to the wrong site for another week.
  `FindMissingRatingOrLinkAsync` therefore takes an entry that has a rating but no link, with no re-attempt window on that half, and it can't loop because a title the provider has no id for gets no rating either.
- **Refresh safety, all deliberate:** the pass upserts one `$set` per rating key (never replacing the `ratings` map, or an ordinary refresh would discard the expensively-obtained IMDb value), it prunes what it didn't rewrite **only after completing** so a failed or empty pass leaves last week's ranking serving, and staleness is read from the ***oldest*** `refreshed_at` in a ranking rather than the newest, since a pass that died halfway leaves its written entries freshly stamped.
- The refresh rides `ReferenceSyncBackgroundService`'s existing 24h tick and lease on its own 7-day staleness window, and the admin's `POST /api/reference-data/sync-now` covers it on the same window pair, so there's no separate Explore admin endpoint.
  `?exploreOnly=true` runs the ranking rebuild without the five reference domains or the finished-show reconciliation, reports `ReferenceSyncStage.RefreshingExplore` throughout and leaves every reference count at zero, which the admin page hides rather than printing as "0 checked".
- **Gotcha:** neither provider has a curated top-rated endpoint, and ordering a whole catalogue by a plain average ranks a single-vote unknown above every classic.
  IGDB reports a vote count per game, so its ranking uses a real floor (`MinUserRatingCount`/`MinCriticRatingCount`), and that floor is deliberately its only filter.
  RAWG exposed no vote count at all, so `GetTopRatedGamesAsync` constrains the pool server-side with `metacritic={MinMetacritic},100`, the closest equivalent of a minimum vote count at no extra call.
  Don't filter client-side instead: the paging loop stops on an empty page, so a filter that can empty one would silently truncate results.
- **The "already have it" exclusion needs both halves**: by provider id (`FindLinkedReferenceIdsAsync` resolved to those documents' `ExternalIds[provider]`) and by title (`FindDistinctTitlesAsync` plus `TitleNormalizer`), because automatic resolution gives up on multiple candidates so a manually-added item may have no link at all.
  Two different works sharing a title collapse under the fallback, an accepted trade.
  **The title half matches with `NormalizeLoose`, not `Normalize`**, because after a link the owner's item carries the *linking* provider's canonical title while the catalogue carries the *discovery* provider's.
  **Both halves are only ever as good as adoption is**, so a domain whose discovery provider changed needs its reconciliation queue drained (`docs/findings/sync-explore-and-import.md`).
  `IExploreSourceRepository` declares both projections once and `ExploreExclusionQueries` implements them for every domain, each repository contributing only a field expression.
  Resolving those reference ids to provider ids goes through `I<X>ReferenceRepository.FindExternalIdsAsync`, a **projected** read over `external_ids` alone, not `FindByIdsAsync` which fetches whole documents (including, for TV, the entire embedded episode guide).
- `explore_dismissal` is keyed `{owner_id, item_type, external_source, external_id}` (unique) on the *provider's* id, since a suggestion usually has no reference document yet.
  `external_source` is the **discovery** provider (`tmdb`/`igdb`), not the rating source, since RAWG and TMDB ids are both plain integers with nothing but an explicit provider to keep them apart.
  `ExploreRankings.DiscoverySource` is the one place a domain's provider is named.
- **Adding goes through `POST /api/explore/{type}/add/{externalId}`, not the ordinary create**: it creates the item then calls `Resolve*Async` with the *exact* provider id, awaited, so the card only disappears once genuinely linked.
  The ordinary create's auto-resolve is a title search that only links on a single candidate, which acclaimed titles routinely fail.
  Free-tier quota is enforced here via `FreeTierQuota.CheckAsync`.
  The controller is plain `[Authorize]` (movies and TV are free tier) with video games member-gated per request (`RequireAccessTo`, 403), and the page hides the tab behind `<AuthorizeView Policy="MemberOnly">` and falls back to Movies.
- **Paging is a rank cursor (`?after=`), never skip/limit**, because the per-caller exclusions are applied *after* the ranked read: with a skip, every title filtered out of one page shifts the next page up and silently drops suggestions.
  `ExploreSuggestionPageDto` carries `NextCursor` (null = ranking exhausted) and `CataloguePending`, since "not built yet" is an empty list too but means the opposite of "you've seen everything".
  The service advances the cursor over *every entry examined*, not just those kept, so a page may come back shorter than requested and still have more behind it.
- `ExplorePage.razor` keeps the active tab in `?tab=`, holds one `TabState` (items plus cursor) per tab, and appends below the current cards rather than reshuffling, both for the explicit "Load more" and for the automatic top-up after an add or dismiss, which share `AppendNextPageAsync`.
  That top-up used to re-request page 1 and diff it, so it re-paid for the same suggestions on every action and could only backfill from titles already shown.
  Add and dismiss share one `ActAsync`.

## Blazor app

`InventoryPageBase<TDto>` centralizes list, paging, search and filter state and calls `InventoryApiClientBase<TDto>`.
A concrete page supplies only its `Api` and `CloneItem`, plus a `protected virtual ExtraQuery` override for its own filters.
Pages that aren't generic CRUD lists (detail pages, Watch Next, Import) build their own layout on the shared `kt-*` classes in `app.css`, with their API clients in their own feature folder.

**List state lives in the URL query string** (`?search=&page=&sort=` plus lowercase per-filter params), read back via `[SupplyParameterFromQuery]`.
Search, filter and pagination clicks never call `LoadAsync`: they navigate via `ApplyQueryChanges`/`ToggleFilter`/`SetFilter`, and the reload happens once in `OnParametersSetAsync`.
This is what makes browser-back from a detail page restore the exact list position, and it means a click and a back/forward share one code path.
A new filter therefore needs exactly three things: a `[SupplyParameterFromQuery]` property, an `ExtraQuery` entry (API-facing key, for example `IsFavorite`), and a button calling `ToggleFilter`/`SetFilter` with the URL param name (for example `favorite`).
Don't add a mutate-then-`LoadAsync` handler.

**List ordering is deterministic everywhere.**
`MongoDbRepositoryBase.FindAllAsync` sorts every page read, defaulting to `_id` descending (ObjectIds embed creation time, so no created-at field is needed) with `_id` appended as tie-break under every other key, since an unsorted skip/limit page can duplicate or drop items across pages.
`PagedRequest.Sort` carries a `ListSort` key (`title`, `rating`) end-to-end, and a repository opts in by overriding `SortTitleField`/`SortRatingField` with an **expression**, never an element-name string (`Car.Name` stores as `commercial_name`, which a string sort would silently miss).
Unknown keys fall back to newest-first.
The title sort attaches a per-query `Collation` ("en", strength 2) for case and diacritic-insensitive ordering with no shadow field and no new indexes.

- **Gotcha:** MongoDB rejects a collation combined with a `$text` filter.
  This is safe today only because every `GetFilter` searches via regex `Contains` (the base's `builder.Text` default is effectively dead), so a future `$text`-searching repository must gate the collation.
- `InventoryList`'s search box keeps a deliberate local copy of the text (so a parent re-render racing fast typing can't revert characters) and adopts an external `Search` change only when it didn't originate from its own `OnSearchChanged`.
  Read the sent/received tracking in `OnParametersSet` before touching it.
- **`SuggestInput`'s menu must never be torn down by the blur its own click causes** (`@onmousedown:preventDefault` on the item and the menu, plus the `_menuMouseDown` guard).
  Blazor Server processes one event at a time per circuit, so the `focusout` a suggestion click fires runs its handler **to completion**, closing the menu and disposing the item's click handler, before the click that caused it is ever dispatched.
  A `Task.Delay` cannot fix this either, for the same reason.
  A mousedown-based guard is the only ordering that works, since it reaches the server before the focusout it causes.
- **Typing highlights a match immediately** (`DefaultActiveIndex`, the exact match if the text already is one, else the first), the ARIA combobox pattern's *automatic selection* variant.
  With manual selection nothing is highlighted until the down arrow is pressed, so **Enter completes nothing** and every keyboard completion costs a trip to the arrow keys.
  An empty field highlights nothing, since it must never complete to whatever sorts first.
- **Enter takes the highlight, Tab only takes one the user moved to with the arrow keys.**
  Enter is a committing key, Tab is a *navigation* key, and auto-completing on Tab silently rewrites a genuinely new value into an existing one that merely contains it ("Dr Kim" tabbed away into "Dr Kimura").
  Escape drops the highlight, which is what lets the next Enter or Tab keep the literal text.
  There's deliberately no `preventDefault` on keydown, since Blazor can only decide it per render and a blanket one would swallow the characters being typed.

**Gotcha:** a `string`-typed component `[Parameter]` needs the `@` prefix.
`Title="_movie.Title"` binds the **literal text**, not the value, because Razor only infers C# when the parameter type couldn't accept a string literal (`Year="_movie.Year"` on `int?` works unprefixed).
It compiles and renders fine, and the bug shows up only in the data, which is how `InlineReferenceLinker` once searched TMDB for the literal `_movie.Title`.
Always write `Title="@_movie.Title"`.

**A page must never render after the user has navigated away** (`Home.razor`'s `ShouldRender`).
Blazor renders a component automatically when its async initialisation completes, and enhanced navigation swaps the DOM while that component is still mounted, so a page still loading when its link is clicked paints itself back over the destination.
Measured on the home page, whose load is `/api/stats`' eleven sequential counts: the destination rendered at 0.79s and the dashboard was back at 1.02s, with the URL and the sidebar's active item both still on the destination.
Rendering only while the browser is still on the page's own route is the fix, and the circuit's `NavigationManager` is told about an enhanced navigation so it is a reliable test.
Any page whose initialisation can outlive a click needs the same guard.

**A detail page's own poll must never re-read over the user** (`Components/Shared/PendingReferenceLink`).
Creating an item resolves its reference on a detached background task, so a just-created item is unlinked when the detail page first fetches it, and the poll re-reads until the link lands.
The catch is that a re-read replaces the page's **whole model**: one issued before a save and answered after it restores the pre-save item, from where the next save writes it back to the server.
So the poll stops at the page's first save (`_edited`, set *before* the PUT) **and** the poll's own read discards its answer if a save landed while it was in flight, since the loop's guard cannot see that second window on its own.

**Scaling is an app-level design here, not an infrastructure assumption**, since the app may sit behind a Cloudflare tunnel with no cookie affinity so nothing may rely on sticky sessions.
`DataProtection:MongoDb:*` (opt-in) persists the key ring via `DataProtection/MongoDbXmlRepository` so cookies and antiforgery tokens decrypt on every replica, and without it multi-replica cookie auth breaks.
This is the only reason `BlazorApp.csproj` references `MongoDB.Driver` (it still never references `Domain`/`Infrastructure.MongoDb`).
`Features:IsWebSocketsOnlyEnabled` (default `true`) starts the circuit with `skipNegotiation` plus WebSockets-only, pinning a circuit to the pod owning its state.
Set it `false` only behind a proxy that can't pass WebSockets, and stay single-replica there.

### Missing pages and missing items: 404, never the error page

`Components/Pages/NotFound.razor` is reached three ways and has to work in all of them: `UseStatusCodePagesWithReExecute("/not-found")` re-executing an unknown URL on a full page load (so the path must stay routable), the Router's `NotFoundPage` on an in-circuit navigation, and `NavigationManager.NotFound()`.
It carries `[ExcludeFromInteractiveRouting]`, which `App.razor`'s `RenderModeForPage` reads: the page renders statically so the cascaded `HttpContext` is actually available, and a bogus URL never opens a SignalR circuit just to say "no".
It reads the original status from `IStatusCodeReExecuteFeature` because the middleware re-executes onto this path for **every** 400 to 599 with no body of its own, and a status below 400 means the page was opened through its own route and is relabelled 404.
No `[Authorize]`: bouncing a signed-out visitor to login would tell them the page exists.

**A missing *item* is a 404 too, and every layer has to agree.**
Three separate things once turned a dead item link into the generic error page (`docs/findings/blazor-ui.md`):

- `InventoryApiClientBase.GetOneAsync` returns null only for a 404 and still throws for everything else.
  It used `GetFromJsonAsync`, whose `EnsureSuccessStatusCode` made an ordinary 404 throw, leaving each detail page's existing "not found" state unreachable.
- `MongoDbRepositoryBase` treats an id that isn't a valid ObjectId as naming no document (`FindOneAsync`/`UpdateAsync`/`DeleteAsync`/`DeleteAllByParentAsync`).
  The driver otherwise raises `FormatException` from `ObjectId.Parse` for a hand-edited or truncated id, which becomes a 500.
  Only a real-MongoDB test proves this (`MalformedIdResourceTest`).
- A detail page fetches its parent **before** its child collection and returns early when the parent is null, since the child query filters on that same id and would fail the whole page.

### Theme

Dark-only: no light theme, no toggle.
`App.razor` sets `data-bs-theme="dark"` statically on `<html>`, server-rendered, so there's no flash on first paint or between navigations.
**Don't reintroduce `data-bs-theme` as something client-side JS sets**, since enhanced navigation re-fetches and diffs the whole document, stripping anything not in the server-rendered markup.
System-ui fonts only, no webfonts.

A JS initializer (`wwwroot/Keeptrack.BlazorApp.lib.module.js`, autoloaded by name, never add a manual `<script>` tag) is the place to hook `blazor.addEventListener('enhancedload', ...)` if any future client-side DOM state needs re-applying.

**Icons are plain Unicode with text presentation** (`◈ ✓ ✕ ★ ▶ ↻ ⌂ ⚙ ♪ ◼ ▭ ▬ ◆`), never a codepoint that renders as a color emoji.
**Gotcha:** looking like a plain symbol isn't enough.
`⭐` (U+2B50) and `👁` (U+1F441) have `Emoji_Presentation=Yes` and render in color everywhere, and were replaced by `★` (U+2605) and `▶` (U+25B6).
Check a new codepoint's default presentation before using it, never append U+FE0F, and drop a symbol entirely rather than force a semantic near-match when the label text already carries the meaning.

`.kt-icon-spin` rotates an icon in place for in-progress states instead of an hourglass emoji.
**Gotcha:** it must stay `display: inline-flex`, never `inline-block`.
Every use wraps an `<Icon>` (an inline `<svg>`), and an inline-block box aligns that on the text baseline, so the box gains the font's descender space and `transform-origin: 50% 50%` lands below the icon's real centre, which makes it orbit rather than spin.
`inline-flex` makes the svg a flex item so the box hugs it exactly.

**The sidebar is the exception, and inline SVG is how to grow past a glyph** (`Components/Layout/NavIcon.razor`, one `switch` over 21 paths).
The rule above bans codepoints whose default presentation is a color glyph, it never banned drawing.
A column of geometric primitives (`◼` Movies over `▭` TV shows over `▬` Books) is indistinguishable at 16px in a vertical list and carries no meaning.
`stroke="currentColor"` means each icon inherits the nav link's own color, so there is nothing extra to theme, no webfont, and no request a CSP or an offline deployment could fail.
Reach for it anywhere a glyph would be a semantic near-match, as `InventoryList`'s search icon does.
Nav rows are grouped by three `.kt-nav-group` labels, and **Manage** sits inside the `MemberOnly` block on purpose so a free preview account never gets a heading over an empty group.

**A media detail page's hero is `DetailHero.razor`**, not a Bootstrap column split: cover on the left at a real size (230px portrait, 260px square), fields on the right, stacking below 767px with the cover *capped* rather than full-bleed.
The component owns the "no cover means single column" rule, the per-shape sizing and the breakpoint, and renders the fields `.row` itself, so a page supplies only `col-*` children.
Video games (`.kt-game-banner`, full-width key art) and Gear/Collectibles (`.kt-product-cover-box`, "contain" so a product photo is never cropped) deliberately stay out of it: different needs, not the same layout done differently.

**A video game's artwork is a full-width banner, and that follows from the stored data rather than from the provider's documentation.**
Counted on the real collection: 329 of 345 references carry RAWG key art (measured 1536x864 and 1438x810, exactly 16:9) and 16 carry IGDB box art (810x1080 portrait), because a stored RAWG image is never overwritten by another provider (`PreferredImageUrl`) even though IGDB is now the default.
Wide is the shape this page is built around, so shrinking the banner into a `DetailHero`-style side column to suit the portrait minority makes the page worse for 95% of the collection.
**Count the collection before redesigning around an aspect ratio**: `db.videogame_reference.find({}, {image_url: 1})` grouped by host answers it in one query.

What was wrong with the old `width: 100%; max-height: 320px; object-fit: cover` is the cropping, for *both* shapes: it makes a box far wider than 16:9, so key art lost the top and bottom of every frame and a portrait cover was cut to a strip.
So `.kt-game-banner` is a plain `aspect-ratio: 16 / 9` box holding the art with `object-fit: cover`, which crops nothing at all for the ordinary case and takes a few percent off one edge of the handful that are 16:10 or wider.
The few portrait covers are cropped hard by the same rule, deliberately: a zoom into the middle of the box art is preferred over empty bands either side of it, and `object-position: center 40%` biases that crop upward because box art carries its title at the top.

**The banner is not wrapped in a card**, and that was owner feedback after it briefly was.
It needs no surface, border or padding of its own, a card only inset the artwork and added a gap the rest of the page does not have, and `.kt-form-card`'s own padding is declared later in `app.css` so a bare `.kt-game-banner-card { padding: 0 }` lost the cascade to it anyway.
The banner takes the same width as the cards below it and its height follows from the ratio.
The page sits in its own `.kt-game-page` column (920px) rather than `.content`'s 1100px, so the artwork, the fields and the platform cards share one width and the synopsis lines stay shorter than the banner above them.

**`.kt-corner-flag` is the "watched"/"read" toggle, and it stays a corner flag on purpose.**
It was briefly moved into the header row beside Favorites/Watchlist/Wishlist for consistency, and that was wrong.
Whether a film has been seen or a book read outranks those three, and their `.kt-toggle-btn.active` accent blue means *flagged* where this one's `--kt-success` green means *finished*.
It is a real `<button>` with `aria-pressed`, and its top-right radius is the card's **inner** radius (`calc(var(--kt-radius-lg) - 1px)`) so it nests into the corner instead of overhanging the card border.

**Before assuming an `app.css` rule applies, check for a scoped `{Component}.razor.css`.**
CSS isolation compiles an extra scope attribute, so a scoped selector always wins over an equally-specific shared one.
This is why `ReconnectModal` kept its scaffolded white and blue colors despite an `app.css` override.

## Tests

- `test/WebApi.UnitTests`: xunit v3, pure logic (import parsers, `WatchNextService`, metrics services, `FreeTierTest`, resilience wiring).
  Mapper validation is compile-time now (Mapperly diagnostics), not a test.
- `test/WebApi.IntegrationTests`: xunit v3 against a real Kestrel host (`KestrelWebAppFactory<Program>`) and real MongoDB.
  `ResourceTestBase` gives typed `GetAsync`/`PostAsync`/`PutAsync`/`DeleteAsync`/`PostFileAsync`, an `Authenticate()` that gets a real Firebase bearer token, and `AuthenticatedUserId`.
  `TvTimeFixtureZipBuilder` builds a synthetic export in memory, never commit a real personal export.
  **A test whose subject is a live third-party provider calls it through `GetThroughLiveProviderAsync`/`PostNoContentThroughLiveProviderAsync`**, which skip on a 502 so a third-party outage can't red the build while a 500 still does.
  `BookProviderSearchAndLinkResourceTest` is the pattern: a `[Theory]` over more than one provider, so whichever is up still proves the search-and-link path.
  Never widen that skip past 502.
- `test/Testing.Shared`: shared hosting and Firebase infrastructure for both suites, not a test project.
  `KestrelWebAppFactory<TEntryPoint>` takes its env-var name and config overrides as constructor parameters so each host supplies its own.
- `test/BlazorApp.PlaywrightTests`: Playwright e2e (`Microsoft.Playwright.Xunit.v3`'s `PageTest`, plain facts, no Gherkin).
  Every test self-skips unless `E2E_ENABLED=true`, so a plain `dotnet test` stays green without browsers.
  `E2eFixture` (`[AssemblyFixture]`) hosts both apps in-process, signs in once for the whole run, and seeds a synthetic book reference.
  `Pages/PageBase` holds nav locators and `Open<X>Async()` helpers, `ListPage` is one class parameterized by route and title for all ten list pages, detail-page title inputs share `.kt-title-input`, and a few unlabeled Add-form fields carry a minimal `data-testid`.
  Movie/TvShow/VideoGame/Album smoke tests link real titles against real providers, so `Tmdb__ApiKey`/`Igdb__ClientId`/`Igdb__ClientSecret`/`Discogs__Token` are hard-required and `Rawg__ApiKey` deliberately is not.
  `WatchNextSmokeTest` is in a `DisableParallelization` collection, since it aggregates across the whole shared tenant.
  `ApiHttpClient` is built with `LazyInitializer.EnsureInitialized`, since a plain `??=` caused a real intermittent failure across parallel classes.
  See `CONTRIBUTING.md` for the full `E2E_*` surface and the three run modes.
- Assertions use `AwesomeAssertions` (FluentAssertions-compatible), data via `Bogus`.

**`ExploreSmokeTest`** seeds `explore_catalogue` directly through the hosted `IExploreCatalogueRepository` (`End2EndFixture.SeedExploreCatalogueAsync`, self-hosted mode only): the ranking is otherwise only written by the weekly refresh pass, which the e2e host never runs, so a seeded ranking *is* the whole ranking.
Every seeded entry and every dismissal is removed at the end of the test, and only the two `Add` cases use a real provider id (TMDB 278, IGDB 72), since adding resolves the reference from the exact provider id.
Its list behaviours are `[Theory]`s over **movies and video games**, which differ in more than the page: the video game tab is member-only, its ranking is IGDB's, and its dismissals are recorded in IGDB's id space.
A domain's entry is seeded under **every** ranking `ExploreRankings.Rankings` declares for it, because which one the page reads follows the admin-selected primary rating source, a stored setting no test controls.

**Gotcha: a smoke test must stay in the default *list* view.**
`ItemGridCard` covers its card with an empty Bootstrap `stretched-link` anchor (the clickable area is the `::after` pseudo-element), so the `<a>` itself has no size and Playwright refuses to click it.
`ListPage.OpenItemAsync` therefore only works in list view, which is what every list page renders by default.

**`PageBase.WaitForReadyAsync` reloads once and re-asserts, and both halves of why are measured** (`ExpectWithReloadAsync`, also behind `ListPage.ExpectRowThumbnailAsync`).
A click can change the URL without the content ever swapping: from a failing run's trace, `GET /cars` answered 200 in 223ms, the URL became `/cars`, and the DOM still showed Home seconds later, the prerender-to-interactive gap reached through enhanced navigation.
Waiting longer cannot fix that, since the page will never render.
The second case is a list rendered while a detail page's save is still in flight: that PUT is issued by the *server* over its circuit, so the browser has nothing to wait for.
A reload only ever runs after the assertion has already failed, so it can't turn a passing test green, and if it starts firing often that is the signal to re-investigate rather than to raise a timeout.

`MobileScreenshotTest` is an assertion-free visual harness behind `E2E_MOBILE_CHECK=true`, capturing every page at 390x844 into `E2E_MOBILE_DIR`.

**A failing test's evidence is in `test/BlazorApp.PlaywrightTests/bin/<config>/net10.0/e2e-diagnostics`**: `SmokeTestBase.DisposeAsync` writes a full-page screenshot plus the Playwright trace (unless `E2E_TRACE=off`) there and prints the paths to the test output.
It captures **every context the test opened**, which is why a test needing a clean or anonymous browser calls `SmokeTestBase.NewAnonymousPageAsync` instead of building its own context: a context disposed inside the test body is closed before the diagnostics run.
Capturing never throws, since diagnosing a failure must not replace the failure being diagnosed.

### Which database a suite writes to, and leaving it as it was found

The integration and Playwright suites run against a **real, long-lived MongoDB**, there is no per-test throwaway database.
Two rules follow, and both have been broken expensively.

**Each suite settles its own database, and never `keeptrack_dev`.**
`IntegrationTestDatabase.Name` (`keeptrack_integrationtests`) and `End2EndConfiguration.DatabaseName` (`keeptrack_e2e`) resolve it (`Infrastructure__MongoDB__DatabaseName` / `E2E_MONGODB_DATABASE` override, neither required), and each pushes the resolved name into its host's configuration.
That override is the load-bearing half: unset, the in-process host runs as `Development` and falls back to `appsettings.Development.json`, silently.
`Testing.Shared/Hosting/TestDatabaseGuard.EnsureTestDatabaseName` then vouches for the name the run will actually use (called from `KestrelWebAppFactory`'s constructor and from `End2EndFixture` in self-hosted mode), so a `dev`/`prod`/`staging` name still fails fast.
**Defaulting rather than demanding is deliberate**: an IDE sets test environment variables once for the whole solution, so requiring a variable both suites read meant they could only share one database.
**The Playwright suite no longer inherits the database name at all**: it hosts its apps against `E2E_MONGODB_DATABASE` whatever `Infrastructure__MongoDB__DatabaseName` says, because isolation has to be a property of the suite rather than something a developer toggles between runs.

**Every test removes what it created, on success and on failure.**
Not tidiness: `scripts/mongodb-create-index.js` enforces uniqueness, so yesterday's leftover fails today's run with a duplicate key.
**Register cleanup at the moment of creation**, never as a per-test `try`/`finally`, since a `finally` only covers what was created before the `try` opened.

- `DatabaseTestBase` holds the registry: `TrackCleanup(Func<Task>)`, `TrackDocument(collection, id)`, `TrackDocumentsWhere(collection, filter)` for owner-scoped singletons with no visible id.
  `ResourceTestBase` adds the HTTP-level `CreateAsync` (POST plus register), `TrackResource`, and `TrackResourcesMatching<TDto>` for imports whose ids the test never learns.
  `SmokeTestBase` mirrors it for Playwright (`TrackOpenItem` reads the id from the detail page URL, `CreateItemAsync`, `TrackItemsMatching`).
- `DisposeAsync` **drains** the registry rather than iterating a cached count, since `TrackResourcesMatching` discovers and registers ids at cleanup time.
- Cleanups run under `CancellationToken.None`, never `TestContext.Current.CancellationToken`, which is cancelled exactly when a test times out and leftovers are most likely.
- **Deleting what a test did *not* create is forbidden, with exactly one exception: a scenario whose precondition is "the tenant doesn't already hold this item".**
  `ExploreSmokeTest`'s add is the only one, since Explore's whole contract is to hide what the caller already tracks.
  `SmokeTestBase.RemoveItemsMatchingAsync` clears it up front, matched on the full title rather than the short search term.
  It is only acceptable because `TestDatabaseGuard` refuses any database name containing `dev`/`prod`/`staging`/`preprod`.
  Never reach for it to paper over a missing cleanup, since a failure that leaks is what makes the next run fail.

**Gotcha, and why this class of bug persists: a delete filter that matches nothing looks exactly like a delete that worked.**
`Builders<TEntity>.Filter.Eq("_id", id)` with a `string` id against an `ObjectId` `_id` matches nothing, deletes nothing and reports success, and those tests passed for months while 65 documents piled up.
The typed `Eq(x => x.Id, id)` works, the string-field-name form does not.
`TrackDocument` sidesteps it by filtering over `BsonDocument` and converting the id to an `ObjectId` when it parses (`lease` and `background_job` ids are genuine strings and simply don't).
**Never take a passing exit status as proof cleanup worked, verify with a document-count diff across the run.**

**Reference documents created by linking a *real* provider title are deliberately left in place** (TMDB's "The Terminator", its cast rows, a Google Books volume): shared canonical facts, deduplicated by provider id, so a re-run reuses them and deleting only forces a re-fetch.
Synthetic fixtures are the opposite: made-up ids accumulate and collide with the unique partial index, so they must always be removed and must generate their external id per test (`TestExternalId.New()`).
Fixed-title real-provider smoke tests do clean up, since a leftover there is an accumulating duplicate.

Deleting a TV show **does** cascade to its episodes, like `Car`/`House`/`HealthProfile`, so a test that marks an episode watched only has to delete the show.

**A document with no list page is the easiest one to leak.**
`explore_dismissal` is the current example: dismissing a suggestion writes an owner-scoped document that appears in no UI, nothing else ever deletes, and whose only visible effect is that the title silently never comes back in that account's real Explore feed.
`ExploreResourceTest` and `ExploreSmokeTest` both register the undo (`DELETE /api/explore/{type}/dismiss/{externalId}`) at the moment they dismiss.

**A test that starts a background job leaves data no cleanup can register, so don't let it do real work.**
The `sync-now` tests get their 202 and finish while the job they started runs on against the live providers, writing the real TMDB ranking into `explore_catalogue` minutes later.
Nothing there asserts anything a provider returns, so those classes are hosted through `WebApi.IntegrationTests/Hosting/ProviderlessWebAppFactory` (every provider credential blanked, the sync-disabling override inherited rather than restated): the job still starts, reports its stages and ends, while writing nothing, calling nobody, and spending none of OMDb's real budget.
`ReferenceSyncPollingResourceTest` (opt-in, `REFERENCE_SYNC_POLL_ENABLED`) is the one test that *wants* the live pass and keeps the ordinary factory.
`ServerDerivedDataSweep` (an `[assembly: AssemblyFixture]`, so it disposes after every class and every `KestrelWebAppFactory`) empties `explore_catalogue` and `lease` at the end of a run as the backstop.
It is only safe for derived state the server rebuilds from scratch, in a database `TestDatabaseGuard` has vouched for, and `provider_quota` is deliberately excluded since it is the ledger of OMDb calls really spent.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C# and Razor, LF endings, `var` everywhere, braces required, `_camelCase` private instance fields, `s_camelCase` private static, PascalCase otherwise.
  Avoid `this.`.
- Primary constructors are the norm for controllers, repositories and API clients.
- Nullable reference types are on across `src`, use `required` for non-nullable properties with no sensible default.
- Public `WebApi.Contracts` DTOs and controllers carry XML doc comments, since they feed the generated OpenAPI/Scalar docs.
- Markdown: **never wrap lines**.
  Formatting is applied separately with `npx neatmd .`.
  **Never run markdownlint** (or `npx markdownlint-cli2`), not even to check an edit.

## CI

GitHub Actions (`.github/workflows/ci.yaml`) on push and PR to `main`: a git/markup lint job, a .NET quality job (build, test with coverage, SonarCloud, FOSSA) gated on app changes, and a container image scan for both Dockerfiles.
Equivalent pipelines exist for GitLab CI and Azure DevOps.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms.
Hold every change to this standard, not just new code.

- **No duplicated algorithms or logic.**
  Duplicated data *shapes* (a Model, Entity and Dto mirroring the same fields) are fine and expected, duplicating the logic over them is not.
  Shared behavior belongs in a base class or shared method, following `DataCrudControllerBase<TDto, TModel>` / `MongoDbRepositoryBase<TModel, TEntity>` / `InventoryPageBase<TDto>` / `OwnedItemImportCommitCoordinator` / `SvgChartHelpers`.
- **Every non-trivial piece of logic needs a test**, especially per-type overrides like `GetFilter`, the least-reused code in the solution and where bugs have historically hidden.
- **Don't guess when the information isn't there.**
  Resolution, imports and Watch Next all leave something unresolved rather than shipping a confident wrong answer.
- **A mocked-repository unit test cannot prove serialization or MongoDB semantics.**
  Anything about filters, collation, null storage or index behavior needs a real-MongoDB integration test.
- Before proposing a fix, verify current best practice for the specific library and framework version in use rather than relying on older patterns from training data.
- Known findings from past reviews are in `docs/findings/`, one file per subject with an index in `docs/findings/README.md`.
  This file states the rule each finding produced, that one records what went wrong and how it was proven, so read a findings file when a specific question is open rather than as background.
  Check the index before re-reporting anything, especially `by-design-and-gaps.md`, and add a new finding to the file its subject belongs to.
