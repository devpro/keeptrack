# AGENTS.md

Guidance for coding agents working in this repository.

## Project overview

Keeptrack is source-available (PolyForm Strict 1.0.0, see `LICENSE`, not open source).
It saves and reviews everything read, watched, listened to or played: books, movies, TV shows, albums, video games, plus car, house and health journals.

Three-tier .NET 10 / C#: `BlazorApp` (Blazor Server UI), `WebApi` (ASP.NET REST API), MongoDB.

## Hard rules

**Never run a third party container image on this workstation.**
No `docker run` and no `docker pull` of any image not published by Docker or by GitHub.
Security scanners are invoked as locally installed binaries, never containerised.
A tool with no local install path is left unwired and recorded in `docs/backlog.md`.

**Linters are never run by an agent, and never imitated by hand.**
No `markdownlint`, no `yamllint`, no formatter (the owner applies `npx neatmd .` to Markdown), no `npx` invocation of any of them.
Reading a lint configuration and reshaping text to fit it, or rewrapping a paragraph so a tool would be quieter, is the same thing as running the linter.
An agent that notices prose a linter might flag says so in its report and changes nothing.
Test commands are not linters.

**A subagent, a fork or a background task is never launched without asking first**, even for read-only research.

**Only GitHub Actions published by `github` or `docker` are allowed in workflows.**
Reusable actions owned by this account, in `../github-workflow-parts`, are also allowed.
Anything else is replaced by an explicit command that downloads the official release binary and verifies its SHA256 checksum.

**IstarCI is recommended but optional, and runs from its package.**
The CI is the GitHub Actions pipeline, which IstarCI only runs locally first.
`task ci:setup`, `task ci` and `task ci:logs` use the installed `@devpro/istarci` package, and a clone of IstarCI is for developing IstarCI only (`task ci:from-clone`).

**The harness is Node.js and bash only.**
Python scripts or code is not allowed.

**Test before code when applicable.**
Tests are written before the implementation and versioned as the source of truth for expected behavior.
A regression test is seen failing for the stated reason before the fix, a refactor of untested code gets its test first, seen green against the unmodified code.

**Preserve existing comments and formatting when editing a file.**
Commit only when asked.

## Writing style

These are hard rules too.
They apply to Markdown, code comments, commit messages, chat replies, error message strings and any prose in scripts.
They are the repository's conventions, applied by default: a report states what the repository does, never presents a convention as the reader's request.

**One thought per line.**
Every sentence starts on its own line, and the renderer joins them back into a paragraph, so a diff shows only the sentence that changed.
A sentence that runs long may continue on the next line at a clause boundary, never mid-clause and never to fit a width.
There is no maximum line length.

**A comment says why, not what, and the why is timeless.**
The code says what it does.
A comment records only what cannot be read off it: the failure it prevents, the constraint that made the obvious shape wrong, the alternative rejected and why.
It is written as if it had always been so: never "used to", never "this replaced", never the story of the session that produced it.
"Filters the parent id with `Eq`, since MongoDB allows one `$text` per query" earns its place, "filter by parent" does not.
A comment that would restate the member name, or a paragraph that walks through the method below it, is left out.

**Never use the em dash (`—`) or the en dash (`–`), nor a spaced hyphen standing in for one.**
Use a colon when introducing an explanation, a comma when joining clauses, or a full stop and a new sentence.

**Never use the second person.**
No "you", no "your", not even in placeholders such as `<your-token>`, which reads `<token>`.
The documentation describes the repository, it does not address a reader.
The contribution terms in `CONTRIBUTING.md` are legal text and the one exception.

**Other conventions.**
Use `ini` as the fence language for `.properties` blocks, never `properties`.
Prefer `>` over `→` for UI navigation, for example **Project Settings > Quality Gate**, arrows remain acceptable in diagrams.

## Repository conventions

This file holds what cannot be read off the code: a convention, a decision and its reason, a gotcha measured against a real system, in one or two lines each.
What was done and when is git history's, and how a bug was found and proven belongs to `docs/findings/`.
A sentence that only says something used to be otherwise is deleted rather than kept.

Shell scripts are named in `snake_case` and committed with the executable bit set (`git update-index --chmod=+x path/to/script.sh`), since a script committed as `100644` fails on a fresh clone.

The root `README.md` stays as short as possible.
Shared content lives in `docs/` and is linked, never copied.
`CONTRIBUTING.md` holds only the guided steps to be up and running, and design explanation stays here.
Superseded plans, finished migrations and dated assessments live in `docs/archived/`.
Known debt not yet scheduled is listed in `docs/backlog.md`.

Target platform is Linux, including WSL2, and `bash`.

## Commands

```bash
dotnet restore && dotnet build

dotnet run --project src/WebApi      # https://localhost:5011/
dotnet run --project src/BlazorApp   # https://localhost:7042/

dotnet test                          # Microsoft.Testing.Platform runner, xunit v3
dotnet test --project test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.Services.WatchNextServiceTest.ComputeInProgressShows_*"

docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile

docker run --name mongodb -d -p 27017:27017 mongo:8.2   # required for WebApi + integration tests
```

Integration tests need Firebase test-user credentials and MongoDB settings, as env vars or in a `Local.runsettings` at the repo root (template in `CONTRIBUTING.md`, never committed).

**Gotcha: `--settings Local.runsettings` runs zero tests (exit code 5)**, filtered or not, since the Microsoft.Testing.Platform runner does not read a runsettings file.
On the command line, `scripts/load-runsettings.js` exports its variables instead:

```bash
eval "$(node scripts/load-runsettings.js)"
dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "*WishlistResourceTest*"
```

The PowerShell equivalent:

```powershell
[xml]$rs = Get-Content Local.runsettings
$rs.RunSettings.RunConfiguration.EnvironmentVariables.ChildNodes | Where-Object { $_.NodeType -eq 'Element' } | ForEach-Object { Set-Item -Path "env:$($_.Name)" -Value $_.InnerText }
```

**Never convert those values into plain `NAME=value` lines and source them.**
Sourcing runs each value through shell expansion, so a secret containing `$` silently loses everything from the `$` to the next non-word character, which surfaces as Firebase answering `INVALID_PASSWORD`.
The script single-quotes every value, escapes any embedded `'`, decodes XML entities and skips commented-out variables, and `Set-Item -Value` never re-parses what it is given.

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
  A member a direction genuinely doesn't need gets an explicit `[MapperIgnoreSource]`/`[MapperIgnoreTarget]`.
- **A single-word entity property is stored camelCase, not snake_case**: `CamelCaseElementNameConvention` is registered globally in `InfrastructureServiceCollectionExtensions`, so only multi-word members carry an explicit `[BsonElement("public_reimbursement")]`.
  Repository code names fields with **expressions**, which resolve through the class map.
  Anything written by hand against raw names must use the stored one: an index or a `$rename` naming `Specialty` instead of `specialty` matches zero documents and reports success.
- `OwnerId` uses `[MapValue(nameof(Model.OwnerId), "")]` on DTO to model (a plain ignore won't compile, it's `required`).
  `DataCrudControllerBase` overwrites it from the caller's claims, it is never trusted from client input.
- Read-only feature controllers (`WatchNextController`, `WishlistController`, Car/House metrics, `ReferenceDataController`) use a small one-directional Model to Dto mapper injected by its concrete type.
- An enum used in a Domain model needs a **separate** copy in `WebApi.Contracts` (Contracts doesn't depend on Domain).
  Member names stay identical and DTO mappers set `EnumMappingStrategy.ByName`, so drift becomes a build diagnostic.
  Mongo entities reuse the Domain enum directly.
- A nullable DTO member mapping to a `required` model member needs an explicit fallback: `CommonDtoMappings.ToRequiredString` (attached via `[UseStaticMapper]`).
  `CarDto.EnergyType` (nullable, and a different enum type) has its own hand-written `[UserMapping]` wrapping the generated `ByName` conversion.
- Never name a property bare `Type`: discriminators are `CarHistoryModel.EventType`, `HouseEventType`, `HealthEventType`, `TvShowModel.State`.

**Gotcha: a DTO used by `InventoryPageBase<TDto>` can never have a `required` member.**
That base is constrained `where TDto : IHasId, new()`, and any `required` member breaks `new()` (`CS9040`).
That is why `BookDto.Title`, `CarDto.Name` and friends are nullable while their models are `required`, and DTOs with no `InventoryPageBase` usage (`CarHistoryDto`) mirror `required` in full.

**Data-shape renames need an idempotent migration script** (`scripts/migrate-*.js`, a `$rename` or equivalent, followed by a re-run of `scripts/mongodb-create-index.js`), not just updated `[BsonElement]` attributes, or every pre-existing document silently loses the field.
A C# rename that keeps the stored element name (`[BsonElement("status")]` on `State`) needs none.

### Adding a new trackable item type

Follow `Book`/`Movie`/`Album`/`TvShow`/`VideoGame`/`Car` as the template.
A new type touches every layer:

1. `Domain/Models/<X>Model.cs` plus `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` plus `Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs` (XML doc comments feed the OpenAPI spec).
4. `WebApi/Controllers/<X>Controller.cs`: a one-line class extending `DataCrudControllerBase<TDto, TModel>`, CRUD logic is never duplicated per controller.
5. Register the repository and storage mapper in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`, the DTO mapper in `Program.cs`.
6. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` (extends `InventoryApiClientBase<TDto>`) plus `Pages/<X>.razor`/`.razor.cs` (extends `InventoryPageBase<TDto>`, overrides `ListRoute`).
   The Add form carries only identity fields, everything else is edited on the detail page, which starts with a `<Breadcrumb/>`.
   List rows are uniform media rows rendered by `InventoryList`, the whole row opens the detail page, and there is deliberately no per-row edit modal.
7. Declare indexes in `scripts/mongodb-create-index.js` (natural-key uniqueness, query shapes, partial indexes for sparse flags).
8. If reference-linked: the DTO implements `IReferenceLinkedDto` (server-hydrated `ImageUrl`, ignored both ways in the mapper), the reference repository gets a batched `FindByIdsAsync`, and the controller overrides `OnListMappedAsync` to hydrate covers via `ReferenceImageHydrator`, one batched lookup per page, never one per item.

### Ownership: owned versions, never a stored flag

An item is owned exactly when it has at least one owned copy, so there is no stored `is_owned` flag to drift.

- `Movie`/`TvShow`/`Book`/`Album` embed `List<OwnedVersionModel>` (`owned_versions`): `CopyType` (`Physical` first so it's the default, or `Digital`), optional `Price` (`decimal`/Decimal128, currency-agnostic), `AcquiredAt` (`DateOnly` via `CommonStorageMappings`), `Vendor`, and free-text `Reference` (edition/order number, unrelated to `ReferenceId`).
- Video games have **no** `OwnedVersions`: their per-platform entries carry a `CopyType` and *are* the copies, so a game is owned when `Platforms` is non-empty.
  `VideoGamePlatformModel.ProductName` (the store's own product/edition text) renders through `OwnedVersionFields`' `ExtraFields` slot rather than joining `IOwnedCopyDto`, since no other type has the concept.
- `IsOwned` exists only as a query parameter: repositories translate it to `SizeGt(OwnedVersions/Platforms, 0)`, the `*_owned` partial indexes match that predicate, and storage mappers ignore it both ways.
- Detail pages share `OwnedVersionsEditor`/`OwnedVersionFields` (`Components/Inventory/Shared/`, unnumbered `col-md` columns so an extra column re-shares width), list rows derive the Owned badge from `OwnedVersions.Count > 0`.
  A new copy is a draft card with Save/Cancel, an already-saved copy auto-saves on change like every other detail field, and removing a saved non-empty copy asks through `ConfirmModal`.

### Bulk store/retailer transaction imports

Three importers of the same shape, controller in `Controllers/` and pure parsing/computation in `Domain/Services/`:

- `AmazonImportController`/`AmazonOrderPreviewService`: order-history CSV, keeps only what's Amazon-specific (`FormatOrderReference` = ASIN plus order id, `BuildAmazonProvenanceNotes`).
- `GenericVideoGameImportController`/`GenericVideoGameImportService`: video-game-only transaction CSV (PSN's GDPR export, `Vendor` is a per-row column so any store with that shape works).
- `GenericImportController`/`GenericImportService` (`POST /api/import/generic`, `MemberOnly`): **the store-agnostic default, extended rather than adding another store-specific importer.**
  It reads a canonical, case-insensitive column set (all optional except `Title`).
  A `Type` column sets each row's `ImportMediaType` (`ParseMediaType` tolerates "TV Show", "Video Game", "Film", "Jeu"), a blank or unrecognized value falls back to the per-row picker rather than guessing.
  Aliases cover real headers (`Product Name` to Title, `ASIN`/`SKU` to `ProductId`, `Total Amount` to Price, `Product Condition` to Condition).
  `Vendor` becomes the copy's Vendor and `Website` its `Reference`, and `Condition` is kept on the copy's `ProductName` (owner's request).

The shared engine is never duplicated: `Domain/Services/OwnedItemImportMergeService.cs` (`ComputeCommitPlan`/`FindImportedReferences`, matching by normalized title via `TitleNormalizer`, merging within the same commit batch) returns `Domain/Models/ImportCommitPlan.cs`, and `Domain/Services/OwnedItemImportCommitCoordinator.cs` owns per-type create/merge orchestration for both multi-type controllers.

`ImportMediaType` and `CopyType` exist in both `Domain.Models` and `WebApi.Contracts.Dto`, so a controller importing both namespaces aliases one.

- **An import reference or dedup key needs a per-product disambiguator**: Product Name for PSN, ASIN for Amazon, order id plus product id for generic.
  One PSN transaction bundles several products (three "Far Cry 4" DLC packs), so transaction plus order id collides and silently skips lines as duplicates.
- **`VideoGamesCreated`/`VideoGamesMergedInto` count distinct items, not rows**, since rows sharing a normalized title consolidate into one item.
  `RowsImported` is the per-row count (`RowsImported + Skipped` equals rows submitted) and `SkippedRowTitles` names the rest, so the UI shows "X of Y selected rows imported".

### Child entities (1-to-many owned by another entity)

`CarHistory`/`Car`, `Episode`/`TvShow`, `HouseHistory`/`House`, `HealthRecord`/`HealthProfile` are separate top-level collections referencing the parent by id (`car_id`, `tv_show_id`), not embedded arrays.
They grow unbounded per parent, and features query them across *all* of a user's parents at once (Watch Next), which needs a plain indexed query rather than `$unwind`.
Embed only small, always-together, never-queried-alone data (`TvShowReferenceModel.Episodes`: bounded, always fetched whole).

- `GetFilter` on a child repository filters the parent id with `Eq`, **not** `Text`: MongoDB allows one `$text` per query, so a `Text` id filter throws whenever a free-text `search` is also supplied.
- **Every parent cascades its delete**: its controller overrides `OnDeletedAsync` and calls the child repository's `DeleteAllFor<Parent>Async`, a one-liner over `MongoDbRepositoryBase.DeleteAllByParentAsync` taking the parent-id **expression**.
  A child is only reachable through its parent id, so it would otherwise be orphaned forever.
  Each cascade has a real-MongoDB `*ResourceTest` case, since a mocked repository can't prove the filter matches.

**Car.**
`CarHistoryModel.DeltaMileage` is user-entered (read off the trip computer), not derived, and `CarMetricsService` cross-checks it against consecutive `Mileage` readings to flag typos or skipped entries.
`CarMetricsService` (consumption across a full refill, cost history, mileage warnings, next maintenance due) is a pure singleton exposed via `CarController.GetMetrics`.

- **A refuel's station is a reference** (`CarHistoryModel.StationId` to `car_station`), owner-less like the `*_reference` collections since a station at an address is a public fact.
  A refuel carries no location of its own, `CarHistoryController.OnListMappedAsync` hydrates `StationBrandName`/`StationCity` through `CarStationHydrator`, one batched lookup per page.
  Maintenance and Other entries keep their own location and free-text `Garage`, having no station to inherit one from.
- **Members create stations inline, admins curate them.**
  `POST /api/car-stations` is find-or-create on the natural key (normalized brand, normalized city, postal code, unique index), so the picker never mints duplicates and a member never waits on an admin.
  `/admin/car-stations` (`AdminOnly`) adds the real city and coordinates and merges duplicates.
  `city_normalized` is `""`, never null or missing, or the unique index would collapse every cityless station onto one key.
- **A station in use cannot be deleted, only merged** (409 naming the count), since deleting blanks every referencing refuel's location.
  The merge re-points every entry (`RepointStationAsync`) **before** deleting the absorbed document and fills only the survivor's gaps, adopting the city only when it doesn't collide with a third station's key.
- **The refuel form checks the total against what was pumped, and only warns** (`Common.System/RefuelCostCheck`, shared by `BlazorApp` and `Domain`).
  A receipt legitimately differs from the pump (car wash, loyalty discount), so it never auto-fills or blocks, but a missing cost when one is computable counts as a mismatch.
  The tolerance derives from what the pump display rounds away (volume to 0.01, unit price to 0.001), since a flat constant false-positives on a big tank and misses a real error on a small one.
- `CarHistoryDto.FuelCategory` ("SP95-E10") is offered through `SuggestInput` over `GET /api/car-history/fuel-categories`, like gear categories, both over `MongoDbRepositoryBase.FindDistinctValuesAsync`.

**House.**
Deliberately smaller than Car (owner priority: browsable insurance log plus yearly cost review), with only `HouseMetricsService.ComputeAnnualCostHistory`.
`HistoryDate` is `DateOnly` and reuses `CommonStorageMappings`, and one `Provider` field covers every category.

**Health.**
The parent is a *person* (`HealthProfileModel.Name`), and both controllers are `MemberOnly`.
`HistoryDate` is a full `DateTime` like Car's (appointment time is real data), stamped UTC via an explicit `[MapProperty(Use = ...)]` in `HealthRecordStorageMapper`.
The money model is the French reimbursement flow: `Price`, `PublicReimbursement`, `InsuranceReimbursement`, `NotCovered`.

- A record is *settled* when `price - public - insurance - notCovered == 0` within `HealthMetricsService.BalanceTolerance` (0.005), anything else lands in `HealthMetricsModel.UnbalancedRecords` with the signed missing amount.
- **The balance rule lives only in `HealthMetricsService`**, the journal's "to check" badges come from the metrics' id list and are never re-derived client-side.
- The detail page is journal-first and badge-only (owner feedback): no "to check" list, no chart, no per-row reimbursement column, the yearly table after the journal.
- **`Specialty` and `Practitioner` are free text with suggestions over what this account already recorded** (`GET /api/health-records/suggestions`, both lists in one `HealthRecordSuggestionsDto` since the form needs both at once).
  Owner-scoped and never a shared catalogue: a doctor's name is one account's medical history, not a public fact.

**Charts.**
Charts are Razor components drawing SVG markup (`ConsumptionChart`, `CarCostHistoryChart`, `HouseCostHistoryChart`), never `RenderTreeBuilder` code with computed sequence numbers (`ASP0006`).
Axes are drawn once by `Components/Shared/ChartAxes.razor`, geometry and coordinate formatting live in `SvgChartHelpers`, and each chart keeps its own series drawing.
**SVG coordinates are always formatted with the invariant culture** (`SvgChartHelpers.ToSvg`), since a host under a decimal-comma culture would otherwise write `40,0` and break every chart.
Chart CSS (`.kt-callout*`, `.kt-chart-*`, `.kt-sheet-table`, `.kt-legend-*`) is global in `app.css`.
House's yearly cost chart is a single-series bar chart plus a breakdown table.

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` implements the whole CRUD surface once, reading the caller's `user_id` claim via `ControllerBaseExtensions.GetUserId()` to scope every query and stamp `OwnerId`.
Every controller uses that extension rather than re-reading the claim.

**A record update never changes a reference link** (`DataCrudControllerBase.PreserveServerOwnedFieldsAsync`, over `IReferenceLinkedModel`).
A PUT is a full replace, and a detail page holding a copy fetched before background resolution linked the item would otherwise write the empty link back.
Resolution, the detail page's check and an admin unlink write the link through a repository, not through the CRUD controller.

`ApiExceptionFilterAttribute` logs every unhandled exception, then converts it: `ArgumentException` to 400, a failed provider call to 502, else 500.

- **A third-party provider that timed out, exhausted its retries or tripped its circuit breaker is a 502, not a 500** (`TimeoutRejectedException`/`BrokenCircuitException`/`HttpRequestException`, logged as a warning), so an outage is distinguishable from a defect here.
- **The 502's `{ error }` says what the provider actually did** (`DescribeUpstreamFailure`: its status, unreachable, timed out or circuit-open).
- **`BlazorApp/Components/Shared/ApiResponseExtensions` (`EnsureSuccessOrThrowAsync`/`ReadJsonOrThrowAsync`) is used wherever a failure is shown to a user, never `EnsureSuccessStatusCode`/`GetFromJsonAsync`**, which discard the body.
  They throw `ApiRequestException`, whose `IsUpstreamProviderFailure` tells a provider outage from a defect.
  `InlineReferenceLinker` then names the provider, quotes the detail, and points at the provider picker when the domain has more than one.

**Resilience:** every outbound third-party client chains `.AddStandardResilienceHandler()` on its `AddHttpClient<...>()` registration, a new one included, never hand-rolled (`ExternalProviderResilienceTest`).

`HostOptions.BackgroundServiceExceptionBehavior = Ignore` in `Program.cs` is a backstop, since by default an exception escaping any `BackgroundService` stops the **entire host**.
A background service still catches what it can anticipate.

Read-only cross-entity aggregations (`WatchNextController`, `WishlistController`, `StatsController`, `SystemStatusController`) are plain `ControllerBase` in `WebApi/Controllers/`, with any real computation in `Domain/Services/`.
`WebApi/Import/` and `WebApi/ReferenceData/` use an older feature-folder shape that new code does not extend.

**Wishlist sharing is capability-URL based**: `GET/POST /api/wishlist/shares`, `DELETE /api/wishlist/shares/{id}` (`wishlist_share`, one document per link, `token` unique), plus `GET /api/wishlist/shared/{token}`, the app's **one deliberately anonymous read**, backing a static-SSR `noindex` page at `/shared/wishlist/{token}`.
The 128-bit token *is* the access control: there is no mail infrastructure and it works for unregistered recipients.
Revoking deletes one owner-scoped document, and `SharedWishlistApiClient` is registered **without** `AuthenticationTokenHandler`, which would bounce an anonymous recipient to login.

**Long-running work runs as a background job, never a blocking request**: buffer the input, start the work on a fresh `IServiceScopeFactory.CreateScope()`, return a job id, poll status.
`JobStore<TStage, TResult>` (`WebApi/Jobs/`) is backed by MongoDB (`background_job`, TTL 7 days), since the replica answering a poll isn't the one running the job.
Owner id is checked in the repository query on every read, and a background task resolves its own `JobStore` from its own scope.

**A detached background job runs on `IHostApplicationLifetime.ApplicationStopping`, not an unbounded token.**
Otherwise on shutdown it keeps working against disposed singletons (Mongo client, HTTP clients, IGDB's rate limiter), every step throws `ObjectDisposedException`, and the job reads "Running" forever.
For the same reason, per-item catches that keep one failing document from aborting a run (`ReferenceSyncService`, `ExploreCatalogueRefreshService`) exclude `OperationCanceledException`.

### Auth, tiers and admin settings

- Firebase auth: cookie in `BlazorApp`, JWT bearer validated against Firebase in `WebApi`, `AuthenticationTokenHandler` attaches the bearer to outgoing calls.
- Authorization is **policy**-based: `AdminOnly` = `RequireClaim("role", "admin")`, `MemberOnly` = `RequireClaim("role", "member", "admin")`, registered in both `Program.cs` files.
  Firebase sends a plain `role` claim, which `BlazorApp`'s `AuthenticationController` copies into the cookie principal at sign-in (`FirebaseClaimsBuilder`).
- **Gotcha:** `AddJwtBearer` sets `MapInboundClaims = false`, otherwise the handler renames short JWT claim names to legacy `ClaimTypes.*` URIs and `RequireClaim("role", ...)` never matches.
  A new custom claim is checked against this.
- **Free preview tier:** an account with no `role` claim gets movies and TV shows only, capped at `Features:FreeTierItemLimit` per collection (default 20, `AppConfiguration.GetFreeTierItemLimit`), episodes at 100x that (`EpisodeController.FreeTierLimitFactor`, only to stop a raw-API caller flooding the database).
  Enforcement is API-side: `[Authorize(Policy = "MemberOnly")]` on every restricted controller plus the creation quota in `DataCrudControllerBase.Post` (403 with `{ error }`).
  `NavMenu.razor` hiding sections is UX, never security, and `FreeTierTest` carries a reflection guard asserting each controller's expected policy.
- **Runtime-changeable global admin settings** live in one `app_setting` document (`_id: "global"`, one field per setting) via `IAppSettingRepository`, written with a targeted `$set`.
  A new setting is a new field there, and deploy-time values stay in `AppConfiguration`/env vars.

### Reference data (shared, owner-less)

`tvshow_reference`, `movie_reference`, `book_reference`, `videogame_reference`, `album_reference` and `person_reference` hold provider metadata.
They are the deliberate exception to "every collection has `owner_id`": public facts about a real work, stored once, pointed at by every tenant's `ReferenceId`.

Providers: TMDB (TV/movie), IGDB and RAWG (video games), Discogs (albums), Google Books, Open Library and BnF (books), OMDb (IMDb ratings for TV/movie).
Images are hotlinked from the provider CDN (TMDB's sanctioned pattern), so there is no local image storage.

- These repositories do **not** extend `IDataRepository<TModel>`/`MongoDbRepositoryBase`, both constrained to `IHasIdAndOwnerId` and owner-scoped CRUD.
  A new owner-less collection gets a small purpose-built repository.
- `ReferenceEnrichmentService` is one `partial class` split by domain file, each with `TryLinkExisting<X>ReferenceAsync`/`TryAutoResolve<X>Async`/`Resolve<X>Async`/`Refresh<X>ReferenceAsync`, shared helpers in the core file.
- It is the single place a title and identity resolve to a provider id, and it propagates the result to every tenant's matching document via `I<X>Repository.SetReferenceLinkAsync`.
  Automatic resolution fires from `<X>Controller.OnCreatedAsync` and from `TvTimeImportService` on its own DI scope, never awaited inline.
- `SetReferenceLinkAsync` also sets `Title`, `Year` and per domain `Author`/`Artist`/`Genre`/`Language` from the canonical record, but **never overwrites with nothing**.
  `VideoGameModel.Platform`/`State` describe the tenant's own copy and are never overwritten.
- **Person dedup is by provider person id, never by name** (`ResolvePersonReferenceIdAsync`, covering actors, authors and artists).
  References store only the id and `ReferenceDataController` hydrates names and pictures server-side, which is why those DTO members are `[MapperIgnoreTarget]`.

**Gotcha: "no reference link yet" is null *or* empty.**
Documents written before Mapperly store `""`, so `Eq(x => x.ReferenceId, null)` misses them.
Any "is this string field unset" query copies `TvShowRepository`/`MovieRepository`'s `UnresolvedFilter()`, and only a real-MongoDB test catches this class of bug.

**Gotcha: every `Find*Async` that can find nothing checks `entity is null` before mapping**, `MongoDbRepositoryBase.FindOneAsync` included, since Mapperly throws on a null source.

#### Local aliases

**Every match path asks the local aliases before a provider** (`TryLinkKnownReferenceAsync`, first in every `TryAutoResolve<X>Async`, and the whole of `TryLinkExisting<X>ReferenceAsync`).
A stored alias is an established answer, and re-deriving it through a fuzzy provider search is at best slower and at worst different.

`MatchedAliases` (`List<ReferenceMatchModel>`, `(Title, Year, Creator, Isbn)`) records every combination confirmed to mean this work, merged and never overwritten.
Queries use `Builders.Filter.ElemMatch` so every condition holds on the *same* element, written once in `Infrastructure.MongoDb/Repositories/ReferenceAliasQueries.cs` over `IHasMatchedAliases`.

**An alias carries its domain's whole identity or is not stored** (`Domain/Services/ReferenceAliasRule.cs`), since a half-key answers questions nobody confirmed.

- **Film, show, game: title plus year** (`TitleAndYear`).
- **Album: title plus creator, no year** (`TitleAndCreator`), since one release exists as many pressings under many years.
- **Book: title plus creator, year recorded when known** (`TitleAndCreatorWithYear`), or an ISBN alone.
  The year is recorded but not required: a book with no provider year would otherwise get no alias and be *unlinked* by the next "check for reference match".
- The book lookup is a ladder (`FindKnownBookReferenceAsync`): ISBN, then `(title, creator, year)`, then `(title, creator)` whatever the year.
- `Creator` always comes from the canonical provider response, never from tenant text, and `Isbn` is recorded only on the alias that used it.
- Indexes follow each domain's lookup (`title`+`year`, `title`+`creator`+`year`, `title`+`creator`, partial `matched_aliases.isbn`), or the `ElemMatch` scans the collection.

**The title-only lookup refuses to choose: `FindByTitleAsync` returns a match only when there is exactly one** (`ReferenceAliasQueries.FindSingleMatchAsync`), since ambiguous and no-match are the same answer to a caller that must not guess.
Not applied to `FindByTitleYearAsync` or to the album lookup, where two documents sharing the whole identity are a duplicate to merge.

#### Resolution and confirmation

`Resolve<X>Async` looks up an existing reference **by provider id first** (`FindByExternalIdAsync`), then by the domain's identity, since title text can't prevent duplicates and the provider id is invariant.

External-id indexes are `unique: true` with `partialFilterExpression: { "external_ids.<key>": { $exists: true } }` (not `sparse`, so documents missing the key don't collide on null).
There is **one index per provider that can write a collection**, since a document holds ids from several: books cover `googlebooks`/`openlibrary`/`bnf`, and `person_reference` covers `tmdb`/`discogs`/`googlebooks`/`openlibrary`/`bnf` (`ResolvePersonReferenceIdAsync` is handed the linking client's `ProviderKey`).

`TryLinkExisting<X>ReferenceAsync` backs `POST /api/<collection>/{id}/refresh-reference`, the "check for reference match" control shown on every detail page to every authenticated user.

- It checks local references first and **escalates to the provider when nothing matches** (`Link<X>ReferenceAsync`), linking exactly what resolution on create would have.
- It does **not** short-circuit on an existing `ReferenceId`, since `Title`/`Year` are editable and replacing a bad match is the point.
- On a match it updates the tenant's document, then calls `SetReferenceLinkAsync` with the pre-edit title and year so other tenants benefit.
- On **no** match for a linked item the link is cleared (`ReferenceId = ""`), returning it to the admin queue.
- The title-only fallback runs **even when `Year` is null**, since `FindByTitleYearAsync(title, null)` only matches a reference whose year is also null.
- Editing a field never searches by itself: the button is the only thing that re-resolves.

**Automatic resolution confirms a *named* match, never that a provider returned one row** (`ReferenceMatchRules`, shared by all five domains).
Row counting refuses ordinary titles (TMDB's fuzzy `The Bear` + 2022 returns 8 results) and links titles nobody compared (`Fallout` + 2025 returns one result, and it is "Thirst Trap: The Fame. The Fantasy. The Fallout.").

- **Two identity shapes, a real difference between domains.**
  Film, show and game are title **plus year** (`ConfirmedMatches`), and a single confirmed match links.
  Book and album are title **plus creator** (`ConfirmedCreatorMatches`), the year is a tie-break and never a filter, and several confirmed candidates are printings of one work, so the best one links.
- **An identity field is mandatory for any automatic link** (owner's rule): a year for films, shows and games, a creator for books and albums.
  Without it the item waits for "check for reference match".
- Candidates must agree with the creator the tenant supplied, not with each other ("J.R.R. Tolkien" and "John Ronald Reuel Tolkien" are one author).
- **An exactly-spelled title beats a loosely-matched one**: `NormalizeLoose` drops "the" and parenthesised groups, so the loose tier is used only when nothing matches exactly (`Alien` must not link *The Alien*, `Shogun` still links *Shōgun*).
- **A hard year filter is never the only query asked.**
  TMDB TV's `first_air_date_year` and Discogs' `year` are hard, so those searches run with and without it and union the results.
  TMDB movie's `year` is not hard, so movies are ranked and never widened.
- **A lower unattended-link rate is the design, not a regression** (owner's call): when matching looks too strict, improve the queries, never loosen what counts as identity.

`ReferenceDataAdminController` (`AdminOnly`) handles manual search and link over a 5-way `ReferenceItemType`, with provider-neutral `ExternalId`/`Provider` DTO fields.

#### Providers

**IGDB** is a plain typed `HttpClient` with three differences handled around it.

- It authenticates with a **Twitch app access token**: `IgdbTokenProvider` caches one per process (a token is not a shared quota, unlike OMDb's budget), and `IgdbAuthenticationHandler` attaches `Client-ID` plus bearer and retries **once** on a 401 with a fresh token.
  The renewal margin is capped at half the token's lifetime, or every call would fetch a new token.
- It allows **4 requests/second**, paced by a `TokenBucketRateLimiter` in a singleton (`IgdbRateLimiter`), since `IHttpClientFactory` rebuilds handlers on rotation.
- Queries are **Apicalypse POST bodies**, so a tenant title is escaped before being embedded in a string literal.
- **Handler order is authentication, then resilience, then the rate limiter (outermost first).**
  The limiter sits innermost so its queue wait counts against the resilience total timeout (`HttpClient.Timeout` is infinite), and its bounded queue's synthesized 429 is retried with backoff.
- Missing credentials are supported (`IgdbSettings.IsConfigured`): every call returns an empty result.
- **Gotcha: a stale field name fails silently.** `where category = 0` parses and matches nothing, since the field is now `game_type`.
  Other field notes are in `docs/igdb-api-notes.md`.
- It reports no Metacritic score, and `aggregated_rating` gets its own `igdbcritic` key.
- `first_release_date` is unix **seconds**, and covers are `https://images.igdb.com/igdb/image/upload/t_cover_big/{image_id}.jpg`.

**Open Library** never sends `year` as a filter (`first_publish_year` is the work's original year), and searches `q=` rather than `title=`, which misses regional variants.
`GetBookDetailsAsync` falls back to a `q=key:{workKey}` re-query when the work JSON lacks `first_publish_date`.
It exposes no reliable series, so `BookModel.Series` is not auto-filled.
Its search is the slowest endpoint here (tens of seconds, and 503s), so **the cross-provider rating fallback is guarded**: `AddOpenLibraryRatingFallbackAsync` catches everything but `OperationCanceledException` and keeps the previously stored rating when the lookup never answered.
An optional secondary provider never fails the primary operation.

**An optional narrowing parameter never silently zeroes out results a broader search would find.**
`DiscogsClient` and `OpenLibraryClient` retry without the artist/author when the constrained search is empty (Discogs indexes "Artist (2)"), and `DiscogsClient` asks with and without `year=` and unions them (`Kid A` + Radiohead + 2001 returns only *Amnesiac*).

**A provider's free-text `q=` is not a title field.**
Discogs' `q=` also matches artist, label, credits and tracklist, so `SearchAlbumsCoreAsync` drops candidates whose parsed release title fails `TitleNormalizer.LooselyContains`, inside the core search so the artist retry still sees "nothing".
`release_title=` is precise but ranks badly (`Nevermind` + Nirvana puts the 1991 album fourth), hence filtering.
Open Library's `q=` has the same noise and is deliberately **not** filtered: read `docs/findings/by-design-and-gaps.md` before changing that.

**BnF**'s `and (bib.author ...)` clause is not a strict intersection, so `BnfClient.SearchBooksCoreAsync` re-checks each candidate's author (`AuthorMatches`).
It is the one XML/SRU client, its `ExternalId` is the bare ARK, `dc:creator` "LastName, FirstName (dates). Role" is normalized to "FirstName LastName", and its records carry no cover art.

**Google Books** is the book default (synopses, covers, language, widest catalogue including manga), querying `intitle:`/`inauthor:`, with an `isbn` as the sole query when given.
Its `volumes?q=` endpoint can be down for days while `volumes/{id}` answers, so a "book search is broken" report is diagnosed by curling the endpoint.
`CleanDescription` decodes entities **first**, converts newlines to `<br/>`, then rebuilds only bare `b`/`i`/`br` tags and strips everything else, which is what makes `BookDetail.razor`'s `MarkupString` safe: **a `MarkupString` is never rendered from text that hasn't been through it.**
Thumbnails are upgraded to `https://` against mixed-content blocking.

#### Search policies

**The book search policy is written once in `BookReferenceClientBase`**: ISBN alone, then title plus author, then title alone, widening only on an **empty** step, an ISBN miss included.
A provider supplies only `SearchByIsbnAsync`/`SearchByTitleAsync`, and no book provider sends `year` as a filter.

**Books and video games are the multi-provider domains** (`IBookReferenceClient`, `IVideoGameReferenceClient`, both `IReferenceProviderClient` with `ProviderKey`/`DisplayName`), resolved through `ReferenceClientRegistry<TClient>`.
`Program.cs` registers every provider (typed `AddHttpClient<TConcrete>` bridged via transient `AddTransient<IBookReferenceClient>`, so handler rotation still works), and registration order is the admin picker's order.
`ReferenceData:BookProvider`/`ReferenceData:VideoGameProvider` name the defaults, matched case-insensitively, and an admin picks any provider per action.
A new provider needs only its class plus one registration block, since enrichment code never names a provider.
Admin provider buttons select, and exactly one control triggers search.

**`RefreshBookReferenceAsync` checks every registered provider's key against `ExternalIds`**, otherwise a reference linked through a non-default provider never refreshes.

**The video game search policy is written once in `VideoGameReferenceClientBase`**: `FindGamesByExactTitleAsync` first, unioned with a `RelevancePoolSize` (50) relevance pool, then ranked.
A provider's relevance ranking truncated to five loses the game (`Code Vein` 2019 ranks sixth behind its sequel and DLC).
No video game client sends the year as a filter, so a wrong year costs a place in the list, never the result.

**`ReferenceMatchRules` is the single declaration of "is this candidate that work"**, read by the search ranking, auto-resolution and provider adoption.

- `OrderByBestMatch` ranks by names-the-work (`TitleNormalizer.LooselyEqual`), then year, then title distance (an edition or DLC is the game plus something), then title, never by provider relevance.
- `YearRank` is **three-state**: the requested year, then no year reported, then a contradicting year.
- `ConfirmedMatches` returns only the best year tier any candidate reaches, and a contradicting year never confirms however alone the candidate is.

**`TryAutoResolveVideoGameAsync` links a single *confirmed* match and requires a year**, and this domain has **no** title-only local fallback (IGDB holds eight games named "Resident Evil 2", three from 1998).

`VideoGameReferenceMatchSmokeTest` covers the journey through the real UI and real IGDB, and deletes every reference it creates (`End2EndFixture.RemoveVideoGameReferencesAsync`), since a leftover lets the local lookup answer and hides a broken escalation.
Every regression of this domain is in `docs/findings/video-game-matching.md`.

TV, movie and album stay hard-wired to TMDB and Discogs (provider-named DTOs and keys on purpose, swapping one is a redesign rather than config).

#### Video game providers and reconciliation

IGDB (`igdb`) is the default and RAWG (`rawg`) stays registered for admin search and so its stored `rawg`/`metacritic` values keep rendering.

**Only the default provider is called on refresh**, unlike books: a second provider exists because the first went down, and falling back would make every pass pay a retry-and-timeout cycle against a dead host.
A reference that can't be adopted keeps its data and is stamped as checked so the staleness queue rotates past it.

**A reference linked before the default changed adopts the new provider's id during the sync** (`TryAdoptDefaultVideoGameProviderAsync`), with no migration script.
It requires exactly one candidate whose title matches the reference's with a compatible year, since the reference's own title is canonical data.

- **Failed adoption breaks Explore**: its exclusion asks each linked reference for the discovery provider's id, so an unadopted reference is a tracked game that keeps being suggested.
- `FindAdoptionCandidatesAsync` runs a ladder, widening when nothing **matched** (not when nothing came back, since a relevance search answers with unrelated results), accumulating candidates across rungs:
  exact title (`where name ~ "..."`), the same with `TitleNormalizer.StripDisambiguator` (RAWG's `GoldenEye 007 (1997)`), `TitleNormalizer.ToProviderQuery` (`NieR Automata` finds what `NieR:Automata` does not), trailing words dropped (`MaxTruncatedQueries` = 3, never below `MinTruncatedQueryWords` = 2), and finally every word as a substring (`FindGamesContainingAllWordsAsync`), shortlisted to the eight closest titles.
- Confirmation is always against the **reference's** title with `NormalizeLoose`, never against the query that found the candidate.
  `Normalize` stays strict because it keys stored aliases against tenant text.
- `Marvel's Avengers` is deliberately not adopted unattended: a rule equating it with `Marvel Avengers` would equate `The Sim` with `The Sims`.
- A fruitless attempt is stamped (`ProviderAdoptionCheckedAt` per provider, retried after `ProviderAdoptionReattemptAfter` = 7 days), and the admin action ignores the window.

**Admin provider reconciliation** (`GET/POST /api/reference-data/provider-reconciliation*`, `AdminOnly`, video games only) resolves what adoption refuses to guess, plus duplicates a provider change leaves behind.

- The gap list and duplicate groups are database reads (`FindWithoutExternalIdAsync`, `Exists(..., false)`), and candidates are fetched per row on demand.
- A row can be searched with admin text or a pasted provider URL or numeric id (`FindGameByIdentifierAsync`); `ProviderWebLinks.TryReadIdentifier` treats nothing else as an address, since `Half-Life` looks like a slug.
- `AdoptVideoGameProviderIdAsync` writes the id onto the **existing** document then reuses `RefreshVideoGameReferenceAsync`, never `ResolveVideoGameAsync`, which could mint a second document, and refuses when another document claims the id, naming it.
- `MergeVideoGameReferencesAsync` fills the survivor's gaps, re-points every tenant item (`RepointReferenceAsync`), then deletes the absorbed document.
  `MergedImageUrl` is computed **before** the ids are unioned, since "is this a RAWG image" is "does this document carry a rawg id".

**A stored cover on a RAWG-linked reference is never overwritten by another provider** (`PreferredImageUrl`): RAWG's landscape key art still serves from its CDN and beats IGDB's box art.
RAWG itself is exempt, or re-linking through RAWG would discard the key art it just fetched.

**A provider only overwrites its own sources' ratings** (`MergeProviderRatings`, keyed on `SupportedRatingSources`), and a source it owns but no longer reports is dropped.

#### Ratings

`RatingSourceCatalog` declares every source key a stored value can carry, its scale and `RatingReattemptAfter` (90 days).
A source key is not a provider, so `rawg` and `metacritic` stay declared while stored values carry them.
`RatingSourceOptions` answers which sources a domain offers and which is effective.

- **The video game sources come from the default client's `SupportedRatingSources`**, never a hardcoded list, so switching provider needs no code or migration.
- **A stored override that isn't on offer is ignored, never erased**, which keeps a provider change reversible.
- Movies and TV are a fixed pair (TMDB vs IMDb), since IMDb is a per-title lookup layered on TMDB.
- The admin card and `rating-sources` GET/PUT/`recompute` are generic over `RatingSourceCatalog.SelectableDomains`, and the picker is a `form-select`.
- **A tenant item's denormalized rating carries its source** (`ReferenceRatingSource` next to `ReferenceRating`/`ReferenceRatingScale`), written by every path that writes the value, even when that source has no value.
- **`recompute` opens with `CountLinkedOnOtherRatingSourceAsync`** and returns `(0, 0)` without reading references when nothing differs; an unstamped item counts as different, so the first run backfills.
  It is not a value-drift repair, which is the sync's job.
- **A batch is one projected read and one bulk write** (`RecomputeBatchSize` = 500): `FindRatingsAsync(afterId, limit)` pages by `_id`, and `SetReferenceRatingsAsync` writes one unordered `BulkWrite` of `UpdateMany`, shared in `ReferenceRatingQueries.cs` over `IHasReferenceRating`.
- Books have no selectable source: `BookPrimaryRating` reads whichever key the reference stores, which is why the source is nullable end-to-end.

**OMDb** supplies IMDb ratings keyed by the IMDb id TMDB exposes, optional (`OmdbSettings.ApiKey` nullable).

- **The free tier is 1000 calls/day, so every call goes through `OmdbCallBudget`**: one shared document per (provider, UTC day) in `provider_quota` (TTL 7 days), reserved **before** the call with an atomic filtered upsert, so an over-count is possible and an under-count is not.
  `Omdb:DailyCallBudget` (1000) and `Omdb:InteractiveReserve` (50): `Background` stops short of the reserve, so a user's action is never left unrated.
- **`OmdbClient` never throws for anything OMDb or the network can do**, returning an `OmdbLookupResult`, and both 401s (limit reached, rejected key) mark the day spent.
- **`OmdbLookupResult.Attempted` decides stamping**: "answered with nothing" is recorded, "never asked" leaves no stamp.
- **A backfill the spent quota skipped doesn't stamp `LastEnrichedAt`** (`ImdbBackfillOutcome.Deferred`), or it would wait a full staleness window; a missing key or a failed request still stamps.
- The `/changes` short-circuit would skip IMDb backfill forever, so `BackfillImdbRatingAsync` resolves the IMDb id cheaply via `/{tv,movie}/{id}/external_ids` on the no-change path.
- `RatingsCheckedAt` (per source) remembers a title IMDb has nothing for, checked before the id lookup, carried over on re-resolve, and ignored by interactive paths.
- `RebuildRatingsAsync` keeps the known IMDb value when the call never happened.

#### Export and import

`GET/POST /api/reference-data/export`/`import` round-trip the six reference collections as a zip of JSON arrays.
`FindAllAsync()` exists only for the export, and the export serializes the models so Mapperly keeps it field-complete.

**The import is a background job** (202 plus job id, `GET /api/reference-data/import/{jobId}`), and the upload is buffered on both sides, since a blocking import outlives the client's 100s timeout.

**The import matches by provider id, never by the exported `_id`** (`Domain/Services/ReferenceDataImportService.cs`, one algorithm over six collections via delegates).
Matching keeps the **target's** `_id`, which every tenant's `ReferenceId` points at, and falls back to `_id` only for a document with no provider id.

- **People are imported first**, and every citing document is re-pointed (`Cast[].PersonReferenceId`, `AuthorReferenceId`, `ArtistReferenceId`).
- **A match merges**: `MatchedAliases` and `Ratings` are unioned, `RatingsCheckedAt` keeps the later attempt, and a missing value leaves the target's.
- A provider id another document claims is skipped and reported (`SkippedExternalIds`).
- An IGDB-linked export lands beside RAWG-linked copies of the same games and is reported (`PossibleDuplicates`), never auto-merged, since title text is not identity.
- `ReferenceDataImportResourceTest` covers each domain and provider over real HTTP and MongoDB.

### Keeping reference data fresh

`ReferenceSyncBackgroundService` is an in-process `BackgroundService` on a 24h `PeriodicTimer` with an immediate pass at startup, rather than a Kubernetes CronJob.
Each tick tries `ILeaseRepository.TryAcquireAsync("reference-sync", Environment.MachineName, 1h)`, so one replica syncs per cycle (`LeaseRepositoryTest`).

`ReferenceSyncService.SyncStaleReferencesAsync` is the single algorithm behind the loop and `POST /api/reference-data/sync-now`.
The two differ only by the staleness windows, declared once in `ReferenceSyncWindows` (`Periodic`: 3 days for references, 7 for Explore; `Forced`: zero), guarded by `ReferenceSyncWindowsTest`.
`sync-now?force=true` rechecks everything, and without it runs exactly the background tick.
One failing document never aborts the run, and one generic loop covers five one-line domain arms (`SyncDomainAsync`).

**`I<X>ReferenceRepository.FindStaleAsync(cutoff, limit)` picks and orders the work** (`ReferenceStalenessQueries.cs`): never-enriched first, then least-recently-enriched, capped at `MaxDocumentsPerDomainPerPass` (500), so what a pass misses leads the next one.

**Gotcha: "never enriched" cannot come from the date comparison**, since `Lte(LastEnrichedAt, cutoff)` matches neither null nor missing.
`Eq(field, null)` matches both and BSON sorts null first, proven only by the real-Mongo `ReferenceStalenessRepositoryTest`; `last_enriched_at` is indexed on all five collections.

TV and movie refreshes pre-check TMDB's `/changes?start_date=...` and only bump `LastEnrichedAt` when nothing changed.
IGDB, RAWG, Discogs and the book providers have no equivalent, so they always full-fetch past the cutoff.

**Gotcha:** the service only works when `Features:IsReferenceSyncEnabled` (default `true`, read every tick), which `KestrelWebAppFactory` sets `false` through `ConfigureAppConfiguration` (`UseSetting` doesn't work with a top-level-statement `Program.cs`).
**Every integration fixture uses `KestrelWebAppFactory<Program>`** to inherit that, or it fires real TMDB calls.

### TV Time import

`POST /api/import/tv-time` is a background job.
All of the following is confirmed against real export data.

- `seen_episode_source.csv` alone is incomplete, so `tracking-prod-records.csv` and `-v2.csv` are merged and deduplicated per (show, season, episode), earliest date winning.
- `followed_tv_show.csv` is incomplete too, so `ImportEpisodesAsync` creates shows from watch events and never skips an unfollowed show.
- Movies carry watch dates in `tracking-prod-records.csv` (`entity_type == "movie"`: watch, towatch when unwatched, follow), and `-v2.csv` has no movie data.
- **Idempotency is by stable id, never by title**, since enrichment rewrites `Title`.
  Imported items carry `TvTimeId` (`IHasTvTimeId`, round-tripped on edits): TV Time's show id or the movie's tracking `uuid`, else a deterministic `tvtime_title:<normalized export title>` via `ResolveTvTimeId`, with `BuildIdByTitle` mapping title-only files onto the id-bearing ones.
- `UpsertIndex<TModel>` matches by `TvTimeId`, falls back to title only for a record with no id yet (back-filled once by `BackfillTvTimeIdAsync`), and leaves a record with a different id alone.
- **A matched record is never modified**, so edits made in the app survive a re-import.
- **Gotcha:** a CSV property missing from some files' headers needs CsvHelper's `[Optional]` on top of being nullable, or header validation throws.

### Watch Next

`WatchNextService.ComputeInProgressShows(shows, episodes, referencesByShowId)` reports a show only when its `State` is `TvShowStatus.Current` **and** the reference's episode list has an entry after the last one watched, compared by `(SeasonNumber, EpisodeNumber)`, whose `AirDate` is past or unset.
A show with no reference is excluded rather than guessed at, and `InProgressShowDto.Next*` reports that confirmed next episode.

`FilterMoviesToWatch` excludes a movie once `FirstSeenAt` is set even if `WantToWatch` is still true, since the flag can go stale.
**`WantToWatch` is movie-only**: a "shows to start" surface would be a real Watch Next section, not a flag.

`TvShowDetail.razor`'s episode checklist hides episodes not yet aired, and is a full watch-through checklist once the show has a `ReferenceId` (checking creates an `Episode`, unchecking deletes it), falling back to recorded episodes plus a manual add form without one.

### Explore (discovery)

`ExploreController`/`ExploreService` (`/explore`) suggests top-rated titles the caller doesn't track, with one-click add and dismiss/undo, for movies, TV shows and video games (books and albums answer 400, having no best-of listing).

- **The list originates from the provider, never from local `*_reference` collections**, which only hold titles someone already tracks.
  Sources: TMDB `/{movie,tv}/top_rated` and IGDB `sort {rating|aggregated_rating} desc`.
- **Requests read `explore_catalogue`, never the provider**: a materialized copy of each ranking, rewritten weekly by `ExploreCatalogueRefreshService` (owner-less, a ranking is a global fact).
  `CatalogueDepth` (1000 per ranking) sets how far a user can scroll.
- A **ranking** is a domain plus an ordering, declared once in the injected `ExploreRankings` and derived from `RatingSourceCatalog`, so a game provider gets one ranking per supported source.
  `DisplaySource` falls back to the ranking's own number when the catalogue can't carry a source, and a pass prunes rankings no longer maintained.
- Ordering follows the admin-selected primary rating source.
  Under **IMDb**, movies and TV keep TMDB's order and IMDb only fills the number (backfilled by the refresh from the shared `OmdbCallBudget`), since partial coverage would float unrated titles up.
  `app_setting.explore_use_tmdb` forces TMDB's vote and skips the backfill.
- **A card links to the title's provider page in a new tab** (`ProviderUrl`/`ProviderName`), following the displayed source where possible.
  URLs are **stored per source** (`web_urls`, merged key by key), since IGDB keys pages by slug; `ProviderWebLinks` holds only id-derived ones.
  The IMDb link is stored even when OMDb was never called, and `FindMissingRatingOrLinkAsync` picks up an entry with a rating but no link.
- **Refresh safety:** one `$set` per rating key (never replacing the map), pruning only after a complete pass, and staleness read from the ***oldest*** `refreshed_at` in a ranking.
- The refresh rides the reference sync's tick and lease on its own 7-day window, and `sync-now?exploreOnly=true` rebuilds only the rankings (`ReferenceSyncStage.RefreshingExplore`).
- **Gotcha:** a plain average ranks a single-vote title above every classic, so IGDB uses a vote floor (`MinUserRatingCount`/`MinCriticRatingCount`) as its only filter, and RAWG constrained `metacritic={MinMetacritic},100` server-side.
  Never filter client-side: the paging loop stops on an empty page.
- Explore deliberately does not restrict IGDB to main games: a well-reviewed DLC or remaster is a legitimate suggestion.
- **The "already have it" exclusion needs both halves**: by provider id (`FindLinkedReferenceIdsAsync` to `FindExternalIdsAsync`, a projected read) and by title (`FindDistinctTitlesAsync` with `NormalizeLoose`, since the linking and discovery providers spell titles differently).
  Both are only as good as adoption, and `ExploreExclusionQueries` implements them once over `IExploreSourceRepository`.
- `explore_dismissal` is keyed `{owner_id, item_type, external_source, external_id}` on the **discovery** provider's id (`ExploreRankings.DiscoverySource`), since TMDB and RAWG ids are both plain integers.
- **Adding goes through `POST /api/explore/{type}/add/{externalId}`**: it creates the item then awaits `Resolve*Async` with the exact provider id, and enforces the free-tier quota via `FreeTierQuota.CheckAsync`.
  The controller is plain `[Authorize]` with video games member-gated per request (`RequireAccessTo`), and the page hides that tab behind `<AuthorizeView Policy="MemberOnly">`.
- **Paging is a rank cursor (`?after=`), never skip/limit**, since per-caller exclusions apply after the ranked read.
  `ExploreSuggestionPageDto` carries `NextCursor` (null when exhausted) and `CataloguePending` ("not built yet" vs "seen everything"), and the cursor advances over every entry examined, so a short page can still have more.
- `ExplorePage.razor` keeps the tab in `?tab=`, one `TabState` per tab, and appends below the current cards (`AppendNextPageAsync`, shared by "Load more" and the top-up after an add or dismiss, both through `ActAsync`).

## Blazor app

`InventoryPageBase<TDto>` centralizes list, paging, search and filter state and calls `InventoryApiClientBase<TDto>`.
A concrete page supplies only its `Api` and `CloneItem`, plus an optional `ExtraQuery` override for its own filters.
Detail pages have two bases of the same kind, each concrete page keeping its own `[PersistentState]` properties since persisted state is keyed by the declaring component:

- `ReferenceLinkedDetailPageBase<TDto, TReferenceDto>` for the five reference-linked types: loading, the pending-link watch, `SaveAsync`, and `ReferenceMatchControls` for the check, unlink and toast.
- `JournalDetailPageBase<TParent, TEntry, TMetrics>` for Car, House and Health: owner or shared loading, year tabs, and `JournalEntryModal` with its unsaved-changes check.

Other pages (Watch Next, Import) build on the shared `kt-*` classes in `app.css`, with their API clients in their own feature folder.

**List state lives in the URL query string** (`?search=&page=&sort=` plus lowercase per-filter params), read via `[SupplyParameterFromQuery]`.
Search, filter and pagination navigate (`ApplyQueryChanges`/`ToggleFilter`/`SetFilter`) and the reload happens once in `OnParametersSetAsync`, so browser-back restores the exact list position.
A new filter is a `[SupplyParameterFromQuery]` property, an `ExtraQuery` entry (API key, `IsFavorite`) and a button calling `ToggleFilter`/`SetFilter` with the URL param (`favorite`), never a mutate-then-`LoadAsync` handler.

**List ordering is deterministic everywhere.**
`MongoDbRepositoryBase.FindAllAsync` sorts every page, defaulting to `_id` descending with `_id` as tie-break under every other key, since an unsorted skip/limit page can duplicate or drop items.
`PagedRequest.Sort` carries a `ListSort` key (`title`, `rating`), and a repository opts in by overriding `SortTitleField`/`SortRatingField` with an **expression** (`Car.Name` stores as `commercial_name`).
The title sort attaches a per-query `Collation` ("en", strength 2).

- **Gotcha:** MongoDB rejects a collation with a `$text` filter, safe only because every `GetFilter` searches with regex `Contains`, so a `$text` repository must gate the collation.
- `InventoryList`'s search box keeps a local copy of the text so a racing re-render can't revert characters, and adopts an external `Search` only when it didn't originate there (`OnParametersSet`).
- **`SuggestInput`'s menu survives the blur its own click causes** (`@onmousedown:preventDefault` on item and menu, plus `_menuMouseDown`): Blazor Server runs the `focusout` handler to completion before the click is dispatched, which no `Task.Delay` fixes.
- **Typing highlights a match immediately** (`DefaultActiveIndex`, the ARIA combobox automatic selection), so Enter completes; an empty field highlights nothing.
- **Enter takes the highlight, Tab only one reached with the arrow keys**, since completing on Tab turns "Dr Kim" into "Dr Kimura"; Escape drops the highlight, and there is no `preventDefault` on keydown.

**Gotcha: a `string`-typed component `[Parameter]` needs the `@` prefix.**
`Title="_movie.Title"` binds the literal text and still compiles, since Razor infers C# only when the parameter type can't accept a string (`Year="_movie.Year"` on `int?` works), so it is always `Title="@_movie.Title"`.

**A page never renders after the user navigated away** (`Home.razor`'s `ShouldRender`): a page still loading when a link is clicked otherwise paints itself back over the destination.
Any page whose initialisation can outlive a click needs the same guard.

**A detail page's pending-link watch never reads over the user** (`PendingReferenceLink`, driven by `ReferenceLinkedDetailPageBase`).
It replaces the page's model only when the fresh read is linked, since a replaced model swaps the objects a pending action holds (a copy awaiting its removal confirmation then removes nothing and is saved back).
It stops at the first save (`MarkEdited`, called before the PUT), and discards an answer when a save landed while the read was in flight.

**Scaling is designed in, never assumed**, since the app may sit behind a Cloudflare tunnel with no sticky sessions.
`DataProtection:MongoDb:*` persists the key ring (`DataProtection/MongoDbXmlRepository`) so cookies decrypt on every replica, the only reason `BlazorApp.csproj` references `MongoDB.Driver`.
`Features:IsWebSocketsOnlyEnabled` (default `true`) pins a circuit to its pod, and is set `false` only behind a proxy without WebSockets, single-replica.

### Missing pages and missing items: 404, never the error page

`Components/Pages/NotFound.razor` is reached by `UseStatusCodePagesWithReExecute("/not-found")` on a full page load, by the Router's `NotFoundPage` in-circuit, and by `NavigationManager.NotFound()`.
It carries `[ExcludeFromInteractiveRouting]` so it renders statically with the `HttpContext` available and opens no circuit, reads the original status from `IStatusCodeReExecuteFeature` (relabelling below 400 as 404), and has no `[Authorize]`, which would reveal the page exists.

A missing *item* is a 404 at every layer:

- `InventoryApiClientBase.GetOneAsync` returns null for a 404 only, and throws for everything else.
- `MongoDbRepositoryBase` treats an invalid ObjectId as naming no document, instead of a `FormatException` 500 (`MalformedIdResourceTest`).
- A detail page fetches its parent **before** its children and returns early when the parent is null.

### Theme

Dark-only: `App.razor` sets `data-bs-theme="dark"` statically on `<html>`, server-rendered, so there's no flash.
It is never set client-side, since enhanced navigation diffs the whole document and strips it.
System-ui fonts only, no webfonts.

`wwwroot/Keeptrack.BlazorApp.lib.module.js` is autoloaded by name (never a manual `<script>` tag) and is where `blazor.addEventListener('enhancedload', ...)` re-applies client-side DOM state.

**Icons are Unicode with text presentation** (`◈ ✓ ✕ ★ ▶ ↻ ⌂ ⚙ ♪ ◼ ▭ ▬ ◆`), never a codepoint with `Emoji_Presentation=Yes` (`⭐`, `👁`), never with U+FE0F.
A symbol that would only be a semantic near-match is dropped when the label carries the meaning.

**Inline SVG is how to grow past a glyph** (`Components/Layout/NavIcon.razor`, `stroke="currentColor"`), used by the sidebar and by `InventoryList`'s search icon: geometric glyphs are indistinguishable at 16px.
Nav rows sit under three `.kt-nav-group` labels, and **Manage** is inside the `MemberOnly` block so a free account never sees an empty group.

`.kt-icon-spin` stays `display: inline-flex`, never `inline-block`, or the wrapped `<svg>` sits on the text baseline and orbits instead of spinning.

**A media detail page's hero is `DetailHero.razor`**: cover left at 230px portrait or 260px square, fields right, stacking below 767px with the cover capped, and no cover meaning a single column.
Video games (`.kt-game-banner`) and Gear/Collectibles (`.kt-product-cover-box`, "contain") deliberately stay out of it.

**A video game's artwork is a full-width `aspect-ratio: 16 / 9` banner with `object-fit: cover`**, because 95% of stored references carry RAWG's 16:9 key art (count before redesigning around an aspect ratio: `db.videogame_reference.find({}, {image_url: 1})` grouped by host).
Portrait covers are cropped hard on purpose, biased upward by `object-position: center 40%` since box art carries its title at the top.
The banner is not wrapped in a card (owner feedback), and the page sits in a 920px `.kt-game-page` column so artwork, fields and platform cards share one width.

**`.kt-corner-flag` is the watched/read toggle and stays a corner flag**: it outranks Favorites/Watchlist/Wishlist, and its `--kt-success` green means *finished* where their accent blue means *flagged*.
It is a `<button>` with `aria-pressed`, and its radius is the card's inner radius (`calc(var(--kt-radius-lg) - 1px)`).

**A scoped `{Component}.razor.css` beats an equally specific `app.css` rule**, so check for one before assuming a shared rule applies.

## Tests

- `test/WebApi.UnitTests`, `test/BlazorApp.UnitTests`: xunit v3, pure logic.
  Mapper validation is compile-time (Mapperly diagnostics), not a test.
- `test/WebApi.IntegrationTests`: a real Kestrel host (`KestrelWebAppFactory<Program>`) against real MongoDB.
  `ResourceTestBase` gives typed HTTP helpers, `Authenticate()` (a real Firebase bearer) and `AuthenticatedUserId`.
  `TvTimeFixtureZipBuilder` builds a synthetic export in memory, a real personal export is never committed.
  **A test whose subject is a live provider calls it through `GetThroughLiveProviderAsync`/`PostNoContentThroughLiveProviderAsync`**, which skip on a 502 and never on anything wider, as in `BookProviderSearchAndLinkResourceTest`'s `[Theory]` over several providers.
- `test/Testing.Shared`: hosting and Firebase infrastructure for both suites, `KestrelWebAppFactory<TEntryPoint>` taking its env-var name and overrides as constructor parameters.
- `test/BlazorApp.PlaywrightTests`: Playwright e2e (`Microsoft.Playwright.Xunit.v3`'s `PageTest`), self-skipping unless `E2E_ENABLED=true`.
  `E2eFixture` (`[AssemblyFixture]`) hosts both apps, signs in once and seeds a synthetic book reference.
  `Pages/PageBase` holds nav locators and `Open<X>Async()`, `ListPage` is one class for all list pages, detail titles share `.kt-title-input`, and a few unlabeled fields carry `data-testid`.
  `WatchNextSmokeTest` is in a `DisableParallelization` collection, and `ApiHttpClient` uses `LazyInitializer.EnsureInitialized`, since `??=` raced across classes.
  The `E2E_*` surface is in `CONTRIBUTING.md`.
- Assertions use `AwesomeAssertions`, data via `Bogus`.

**`ExploreSmokeTest` seeds `explore_catalogue` directly** (`End2EndFixture.SeedExploreCatalogueAsync`, self-hosted only), since the e2e host never runs the refresh.
It seeds every ranking `ExploreRankings.Rankings` declares for a domain (the one read follows a stored admin setting), uses real provider ids only for the two `Add` cases (TMDB 278, IGDB 72), and its `[Theory]`s cover movies and video games, which differ in tab gating, ranking and id space.

**Gotcha: a smoke test stays in the default list view**, since `ItemGridCard`'s `stretched-link` anchor has no size and Playwright refuses to click it.

**`PageBase.WaitForReadyAsync` reloads once and re-asserts** (`ExpectWithReloadAsync`, also behind `ListPage.ExpectRowThumbnailAsync`): enhanced navigation can change the URL without ever swapping the content, and a list can render before a detail page's server-side PUT lands.
The reload only runs after a failed assertion, and firing often is the signal to re-investigate rather than raise a timeout.

`MobileScreenshotTest` is an assertion-free visual harness behind `E2E_MOBILE_CHECK=true`.

**A failing test's evidence is in `test/BlazorApp.PlaywrightTests/bin/<config>/net10.0/e2e-diagnostics`**, written by `SmokeTestBase.DisposeAsync` for every context the test opened, so a test needing a clean browser calls `SmokeTestBase.NewAnonymousPageAsync`.
Capturing never throws.

### Which database a suite writes to, and leaving it as it was found

The integration and Playwright suites run against a real, long-lived MongoDB, with no throwaway database per test.

**Each suite settles its own database, never `keeptrack_dev`.**
`IntegrationTestDatabase.Name` (`keeptrack_integrationtests`) and `End2EndConfiguration.DatabaseName` (`keeptrack_e2e`) resolve it (overridable by `Infrastructure__MongoDB__DatabaseName` and `E2E_MONGODB_DATABASE` respectively) and push it into the host configuration, since otherwise the in-process `Development` host falls back to `appsettings.Development.json`.
`TestDatabaseGuard.EnsureTestDatabaseName` refuses a name containing `dev`/`prod`/`staging`/`preprod`.
Defaults rather than requirements, because an IDE sets test variables once for the whole solution.

**Every test removes what it created, on success and on failure**, since unique indexes make yesterday's leftover fail today's run.
**Cleanup is registered at the moment of creation**, never in a per-test `try`/`finally`.

- `DatabaseTestBase`: `TrackCleanup(Func<Task>)`, `TrackDocument(collection, id)`, `TrackDocumentsWhere(collection, filter)`.
  `ResourceTestBase`: `CreateAsync` (POST plus register), `TrackResource`, `TrackResourcesMatching<TDto>`.
  `SmokeTestBase`: `TrackOpenItem`, `CreateItemAsync`, `TrackItemsMatching`.
- `DisposeAsync` **drains** the registry, since `TrackResourcesMatching` registers ids at cleanup time.
- Cleanups run under `CancellationToken.None`, since the test token is cancelled exactly on a timeout.
- **Deleting what a test did not create is forbidden**, except `ExploreSmokeTest`'s add, whose precondition is "the tenant doesn't hold this item" (`SmokeTestBase.RemoveItemsMatchingAsync`, full title).

**Gotcha: a delete filter that matches nothing looks exactly like one that worked.**
`Builders<TEntity>.Filter.Eq("_id", id)` with a `string` id against an `ObjectId` matches nothing, while the typed `Eq(x => x.Id, id)` works; `TrackDocument` converts a parseable id to `ObjectId`.
Cleanup is verified with a document-count diff across a run, never by exit status.

**Reference documents linked from a *real* provider title are left in place** (shared, deduplicated by provider id), while synthetic ones are always removed and use a per-test external id (`TestExternalId.New()`).
Deleting a TV show cascades to its episodes.

**A document with no list page is the easiest to leak**: `explore_dismissal` appears in no UI, so tests register the undo (`DELETE /api/explore/{type}/dismiss/{externalId}`) as they dismiss.

**A test that starts a background job must not let it do real work**: the `sync-now` tests use `ProviderlessWebAppFactory` (every provider credential blanked), except the opt-in `ReferenceSyncPollingResourceTest` (`REFERENCE_SYNC_POLL_ENABLED`).
`ServerDerivedDataSweep` (`[assembly: AssemblyFixture]`) empties `explore_catalogue` and `lease` after the run, never `provider_quota`, the ledger of OMDb calls really spent.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C# and Razor, LF endings, `var` everywhere, braces required, `_camelCase` private fields, `s_camelCase` private static, PascalCase otherwise, no `this.`.
- Primary constructors are the norm for controllers, repositories and API clients.
- Nullable reference types are on across `src`, with `required` for non-nullable properties with no sensible default.
- Public `WebApi.Contracts` DTOs and controllers carry XML doc comments, which feed the OpenAPI/Scalar docs.

## CI

GitHub Actions (`.github/workflows/ci.yaml`) on push and PR to `main`: a git/markup lint job, a .NET quality job (build, test with coverage, SonarCloud, FOSSA) gated on app changes, and a container image scan for both Dockerfiles.
Equivalent pipelines exist for GitLab CI and Azure DevOps.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms, for new and existing code alike.

- **No duplicated algorithms or logic.**
  Duplicated data *shapes* (Model, Entity and Dto) are expected, duplicated logic over them is not.
  Shared behavior belongs in a base class or shared method, following `DataCrudControllerBase<TDto, TModel>`, `MongoDbRepositoryBase<TModel, TEntity>`, `InventoryPageBase<TDto>`, `ReferenceLinkedDetailPageBase`, `JournalDetailPageBase`, `OwnedItemImportCommitCoordinator`, `ChartAxes`.
- **Every non-trivial piece of logic needs a test**, especially per-type overrides like `GetFilter`, where bugs have historically hidden.
- **Don't guess when the information isn't there**: resolution, imports and Watch Next leave something unresolved rather than ship a confident wrong answer.
- **A mocked-repository test cannot prove MongoDB semantics**: filters, collation, null storage and indexes need a real-MongoDB integration test.
- Current best practice for the library and framework version in use is verified before proposing a fix.
- Past findings are in `docs/findings/` (index in `docs/findings/README.md`): read when a specific question is open, checked before re-reporting anything (especially `by-design-and-gaps.md`), and extended in the file a new finding's subject belongs to.
