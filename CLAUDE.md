# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Keeptrack is an open source application that lets users save and review everything they read, watch, listen to or play (books, movies, TV shows, music albums, video games, cars/car history).

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
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.MappingProfiles.AutoMapperConfigurationTest.WebApiAutoMapperProfile_ShouldBeValid"

# build container images
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```

A local MongoDB instance is required to run the Web API or the integration tests:

```bash
docker run --name mongodb -d -p 27017:27017 mongo:8.2
```

Integration tests also need Firebase test-user credentials and MongoDB connection settings. Provide them as environment variables, or in a `Local.runsettings` file at the repository root (see `CONTRIBUTING.md` for the template). Never commit this file.

## Architecture

The solution follows a layered / clean-architecture style split across small, single-purpose projects (`src/*`), with `Domain` at the center and no project referencing "outward":

| Project | Depends on | Responsibility |
|---|---|---|
| `Common.System` | — | Cross-cutting primitives shared by every layer: `IHasId`, `IHasIdAndOwnerId`, `PagedRequest`, `PagedResult<T>`. |
| `Domain` | `Common.System` | Business models (`*Model` in `Models/`) and repository interfaces (`I*Repository` in `Repositories/`). No persistence or web concerns. |
| `Infrastructure.MongoDb` | `Domain` | MongoDB implementation: BSON `Entities/` and `Repositories/` implementing the `Domain` interfaces. |
| `WebApi.Contracts` | `Common.System` | Public REST DTOs (`Dto/`), shared between `WebApi` and `BlazorApp` so the Blazor client can deserialize API responses without duplicating classes. |
| `WebApi` | `Infrastructure.MongoDb`, `Domain`, `WebApi.Contracts` | ASP.NET Web API: controllers, AutoMapper profiles, DI wiring, JWT authentication, OpenAPI/Scalar docs. |
| `BlazorApp` | `Common.System`, `WebApi.Contracts` | Blazor Server UI. Talks to `WebApi` over HTTP using the shared DTOs; it never references `Domain` or `Infrastructure.MongoDb` directly. |

### Data model conventions

Every entity that belongs to a user implements `IHasIdAndOwnerId` (`Id` + `OwnerId`) at all three layers (`Domain` model, MongoDB entity, contract DTO), each with its own class. AutoMapper profiles convert between them:

- `Infrastructure.MongoDb/../MappingProfiles`-equivalent lives in `WebApi/MappingProfiles/DataStorageMappingProfile.cs`: MongoDB entity <-> Domain model.
- `WebApi/MappingProfiles/WebServiceMappingProfile.cs`: DTO <-> Domain model. `OwnerId` is always ignored on the DTO -> model direction; it is set server-side from the authenticated user's claims, never trusted from client input.

`AutoMapperConfigurationTest` (in `WebApi.UnitTests`) asserts the whole mapping configuration is valid; add a mapping there whenever a new model/entity/DTO triple is introduced.

### Adding a new trackable item type

Follow the existing types (`Book`, `Movie`, `MusicAlbum`, `TvShow`, `VideoGame`, `Car`/`CarHistory`) as the template. A new type touches every layer:

1. `Domain/Models/<X>Model.cs` and `Domain/Repositories/I<X>Repository.cs` (extends `IDataRepository<TModel>`).
2. `Infrastructure.MongoDb/Entities/<X>.cs` (BSON attributes, `snake_case` element names via `[BsonElement]`) and `Infrastructure.MongoDb/Repositories/<X>Repository.cs` (extends `MongoDbRepositoryBase<TModel, TEntity>`, overrides `CollectionName` and, if searchable, `GetFilter`).
3. `WebApi.Contracts/Dto/<X>Dto.cs` (XML doc comments drive the generated OpenAPI spec).
4. `WebApi/Controllers/<X>Controller.cs`: a one-line class extending `DataCrudControllerBase<TDto, TModel>` — CRUD logic is never duplicated per controller.
5. Register the repository in `WebApi/DependencyInjection/InfrastructureServiceCollectionExtensions.cs`.
6. Add both AutoMapper maps (`DataStorageMappingProfile`, `WebServiceMappingProfile`).
7. `BlazorApp/Components/Inventory/Clients/<X>ApiClient.cs` extending `InventoryApiClientBase<TDto>`, plus a `Pages/<X>.razor` / `<X>.razor.cs` pair extending `InventoryPageBase<TDto>`.

### Child entities (1-to-many owned by another entity)

`CarHistory` (owned by `Car`) and `Episode` (owned by `TvShow`) are separate top-level collections referencing their parent by id (`car_id`, `tv_show_id`), not embedded arrays. This is deliberate MongoDB schema design, not an accident: these child collections can grow unbounded per parent over years of use, and features that need to query the child across *all* of a user's parents at once (e.g. Watch Next, below) need a plain indexed query rather than an `$unwind` aggregation. Embedding is the right call for genuinely small, always-together, never-queried-alone data; neither condition holds here. `EpisodeRepository.GetFilter` filters by `input.TvShowId` with `Eq` (not `Text` — see the `CarHistory` bug in `docs/code-quality-findings.md` for what happens when an exact-id filter uses `Text` instead). New multi-word BSON fields get an explicit `[BsonElement("snake_case_name")]`; don't rely on the `CamelCaseElementNameConvention` registered in `AddMongoDbInfrastructure` — every existing multi-word field already overrides it explicitly, so it's effectively dead configuration. Indexes for new collections are declared in `scripts/mongodb-create-index.js` (natural-key uniqueness, query-shape support, and partial indexes for sparse boolean flags like `is_favorite`/`want_to_watch`).

### Reference data (shared, owner-less)

`tvshow_reference` and `movie_reference` (`Domain/Models/TvShowReferenceModel.cs`/`MovieReferenceModel.cs`, `Infrastructure.MongoDb/Entities/TvShowReference.cs`/`MovieReference.cs`) hold metadata (synopsis, episode titles) fetched from TMDB. They are the one deliberate exception to "every collection has `owner_id`": this data is public facts about a real show/movie, not user content, so storing it once and pointing every tenant's `TvShowModel.ReferenceId`/`MovieModel.ReferenceId` at it avoids duplicating the same show across every user who tracks it. Matching key is normalized title + year (`TitleNormalizer.Normalize`, `Common.System/TitleNormalizer.cs` — shared with `TvTimeImportService` so the two never drift on what counts as "the same title").

These repositories (`ITvShowReferenceRepository`/`IMovieReferenceRepository`) do **not** extend `IDataRepository<TModel>` or `MongoDbRepositoryBase<TModel, TEntity>` — both are hard-constrained to `IHasIdAndOwnerId` and owner-scoped paged CRUD, which doesn't fit a shared lookup table with a different method set (`FindByTitleYearAsync`, `UpsertAsync`). Don't force a new owner-less collection through that base; write a small purpose-built repository instead, like these two.

`TvShowReferenceModel.Episodes` is **embedded**, the opposite choice from the per-tenant `Episode` collection. This isn't inconsistent - the access pattern is opposite too: a reference show's episode list is bounded to its real runtime, always fetched as a whole (rendering a season picker needs all of it at once), and never queried across shows. That's exactly the case CLAUDE.md already says favors embedding; the per-tenant `Episode` collection fails all three conditions (unbounded per-user growth, queried across shows for Watch Next, upserted independently), which is why that one is referenced instead.

`WebApi/ReferenceData/ReferenceEnrichmentService.cs` is the single place that resolves a title+year to a TMDB id and propagates the resulting `ReferenceId` to every tenant's matching document (`ITvShowRepository.SetReferenceIdForTitleYearAsync`/`IMovieRepository`'s equivalent) - both the automatic best-effort match (fired from `TvShowController`/`MovieController`'s `OnCreatedAsync` hook on `DataCrudControllerBase`, and from `TvTimeImportService` after each newly-imported show/movie) and the admin's manual pick (`ReferenceDataAdminController`) call through this one method rather than duplicating the "upsert reference doc, then propagate" logic. The automatic path only ever acts on a *single, confident* TMDB search result - zero or multiple candidates leaves the item unresolved for the admin queue rather than guessing (the same "don't guess when you don't have the info" principle as Watch Next, below).

**Gotcha:** "does this tenant document have no reference link yet" cannot be a plain `Eq(x => x.ReferenceId, null)` filter. `AddAutoMapper` is configured with `AllowNullDestinationValues = false` (`WebApi/Program.cs`), so mapping a model whose string property is null stores an **empty string**, never an actual BSON null. `TvShowRepository`/`MovieRepository`'s `UnresolvedFilter()` matches null *or* empty string for exactly this reason - copy that helper's shape (not a bare null check) for any new "is this string field unset" query. This one is easy to get wrong silently: it doesn't throw, it just quietly matches zero documents. A real-MongoDB integration test (`TvShowReferenceLinkingTest`) is what caught it, not the unit tests (which mock the repository and never see the actual serialization behavior).

Admin-only endpoints (`ReferenceDataAdminController`) use policy-based authorization (`[Authorize(Policy = "AdminOnly")]`, registered in both `WebApi/Program.cs` and `BlazorApp/Program.cs` as `RequireClaim("role", "admin")`), backed by a Firebase custom claim - not ASP.NET's built-in `Roles=` support, since Firebase's claim arrives as a plain `"role"` claim rather than the `ClaimTypes.Role` URI that `[Authorize(Roles=...)]`/`<AuthorizeView Roles=...>` expect by default. `BlazorApp/Components/Account/Controllers/AuthenticationController.cs` copies the `role` claim from the verified Firebase token into the cookie principal at sign-in - WebApi validates the bearer token's claims directly and needs no equivalent step. There's no in-app way to grant the first admin; it's a one-off `setCustomUserClaims` call via the Firebase Admin SDK (see `CONTRIBUTING.md`).

**Gotcha:** `WebApi/Program.cs`'s `AddJwtBearer` sets `options.MapInboundClaims = false` deliberately. Without it, the token handler silently renames certain short JWT claim names to legacy `ClaimTypes.*` URIs before `HttpContext.User` ever sees them - `"role"` is one of the remapped names (to `ClaimTypes.Role`), so `RequireClaim("role", "admin")` would never match even though the raw token genuinely has a `role` claim. This is exactly why the Blazor side (whose cookie principal is built by hand in `AuthenticationController`, using the literal claim name) could show the admin nav link while the same request's bearer-token call to WebApi still 403'd - the two sides were checking different claim types for what was, on the wire, the same claim. `user_id` was never affected by this because it isn't one of the handful of short names the legacy map remaps; don't assume a new custom claim is equally safe without checking, or just leave `MapInboundClaims = false` alone.

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` (`WebApi/Controllers/DataCrudControllerBase.cs`) implements the full CRUD surface (`GET`, `GET/{id}`, `POST`, `PUT/{id}`, `DELETE/{id}`) once, generically. It calls the shared `ControllerBaseExtensions.GetUserId()` extension (`WebApi/Controllers/ControllerBaseExtensions.cs`) to read the caller's `user_id` claim, scope every query, and stamp `OwnerId` on writes, so per-type controllers only need routing and generic type arguments — any new controller (CRUD or not) should call the same extension rather than re-reading the claim. Unhandled exceptions are converted to JSON error responses by `ApiExceptionFilterAttribute` (`ArgumentException`/`ArgumentNullException` -> 400, everything else -> 500).

Not every endpoint is per-item CRUD. `WebApi/WatchNext/` (a read-only cross-entity aggregation) and `WebApi/Import/` (the TV Time GDPR-export upsert, using `CsvHelper` for parsing) are their own feature folders with a plain `ControllerBase` and a small service class, rather than being force-fit into `DataCrudControllerBase`. Follow that folder-per-feature shape for future non-CRUD endpoints instead of stretching the generic CRUD base to cover them.

`seen_episode_source.csv` alone is a drastically incomplete picture of a user's episode history (it's only written when an episode is marked watched via TV Time's episode-detail screen) - confirmed against real export data, not assumed. `TvTimeImportService` also reads `tracking-prod-records.csv` and `tracking-prod-records-v2.csv`, TV Time's generic event logs, which capture episodes marked watched any other way (bulk/season actions). All three are merged and de-duplicated per (show, season, episode), earliest date wins, before upserting `Episode`s. If a future TV Time export field looks suspiciously sparse, check the raw export files directly (`grep` the show name across every `*.csv`) before assuming the current parser set is complete - this is exactly how the tracking files were found.

`followed_tv_show.csv` is not a complete list of shows either - confirmed with a real show ("The Pitt") that has genuine watch history in the tracking files but no row in `followed_tv_show.csv` at all. `ImportEpisodesAsync` creates a show on the fly from watch-event data (title, plus the show's TV Time id when the source file has one, applying the same rating/favorite/notes enrichment a normally-followed show gets) rather than skipping shows that aren't already known. Don't reintroduce a "skip if not already followed" check here.

When a `SeenEpisodeRecord`-shaped property is only present in *some* of the three source files' headers (like `TvShowId`, absent from `seen_episode_source.csv`), it needs `[Optional]` from `CsvHelper.Configuration.Attributes` in addition to not being C#'s `required` - CsvHelper's header validation throws on a missing column for any `[Name]`-decorated property regardless of C# nullability unless that attribute is present. This only surfaces at runtime against a real file missing the column, not at compile time - a unit test with a realistic fixture (matching `seen_episode_source.csv`'s actual header) is what caught it.

The import runs as a background job rather than a single request/response, so the UI can show real progress: `POST /api/import/tv-time` buffers the upload, kicks off the work via `IServiceScopeFactory.CreateScope()` (the request's own DI scope is gone by the time the background work runs), and returns a job id immediately; `GET /api/import/tv-time/{jobId}` reports the current `ImportStage`. `ImportJobStore` is an in-memory singleton keyed by job id and checks the caller's owner id on every read, so a job is only ever visible to the user who started it. Follow this shape (buffer input, background `Task` via a fresh scope, pollable status keyed by owner) for any other future long-running action - don't block a request on multi-second server work just because the current single-endpoint pattern is simpler to write.

Watch Next deliberately reports the *last watched* episode per in-progress show, never a guessed "next" one: Keeptrack has no episode-guide data, so it can't tell whether a further episode exists (the user might already be fully caught up). Don't reintroduce a "+1" heuristic here - it was tried and shipped a real, confirmed-wrong result.

### Blazor app

`InventoryPageBase<TDto>` (`BlazorApp/Components/Inventory/InventoryPageBase.cs`) centralizes list/paging/search/inline-edit state and calls into `InventoryApiClientBase<TDto>`, which wraps the typed `HttpClient` calls to the Web API (its `GetAsync` takes an optional extra-query-parameters dictionary, used by features that filter on more than search/page/pageSize). Each concrete page (`Books.razor.cs`, `Movies.razor.cs`, ...) only supplies its `Api` instance and `CloneItem`. Authentication uses Firebase (cookie auth in the Blazor app, JWT bearer validated against Firebase in the Web API); `AuthenticationTokenHandler` attaches the bearer token to outgoing API calls.

Pages that aren't a generic CRUD list (`TvShowDetail.razor`, `WatchNext/WatchNextPage.razor`, `Import/ImportPage.razor`) don't extend `InventoryPageBase`/`InventoryList` — they're free to build their own layout on top of the shared `kt-*` CSS classes in `app.css`. Their API clients live next to them in a feature folder rather than in `Inventory/Clients/`.

### Theme

`app.css` is a light+dark theme driven by `data-bs-theme` on `<html>` (Bootstrap 5.3's native color-mode support), with Keeptrack's own `--kt-*` tokens layered on top for custom components (sidebar, `kt-table-wrap`, `kt-modal`, etc.). `wwwroot/theme.js` sets the initial theme from `localStorage`/`prefers-color-scheme` before first paint (avoiding a flash of the wrong theme) and exposes `ktToggleTheme()`, called directly from a plain button in `NavMenu.razor` — no Blazor/JS interop needed for the toggle itself. Use system-ui fonts only; no decorative/display webfonts.

Enhanced navigation re-fetches and diffs the whole document on every in-app link click; anything set on `<html>`/`<body>` by client-side JS rather than server-rendered markup (like `data-bs-theme`) gets stripped back out unless it's explicitly re-applied. `wwwroot/Keeptrack.BlazorApp.lib.module.js` is a JS initializer (auto-loaded by Blazor because its name matches the assembly - don't add a manual `<script>` tag for it) that re-applies the theme via `blazor.addEventListener('enhancedload', ...)`. Any future client-side DOM state that isn't part of the Razor render tree needs the same treatment.

Before assuming a rule in `app.css` will style something, check whether that element has its own scoped `{ComponentName}.razor.css` file (Blazor CSS isolation) - a scoped selector always wins the cascade over an equally-specific one in the shared stylesheet, since it's compiled with an extra scope attribute. This is exactly what caused the reconnect-modal (`ReconnectModal.razor.css`) to render with the original scaffolded white/blue colors despite an app.css override that looked like it should have applied; the scoped file itself has to be edited.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C#/Razor, LF line endings, `var` preferred everywhere, braces required, `_camelCase` for private instance fields, `s_camelCase` for private static fields, PascalCase for everything else. Avoid `this.` qualification.
- Primary constructors are the norm for controllers, repositories and API clients (see `BookController`, `BookRepository`, `BookApiClient` above).
- Nullable reference types are enabled across all `src` projects; use `required` for non-nullable properties that have no sensible default (e.g. `BookModel.Title`).
- Public WebApi.Contracts DTOs and WebApi controllers carry XML doc comments (`GenerateDocumentationFile` is enabled) because they feed the generated OpenAPI/Scalar documentation.
- Markdown files: 2-space indent, no trailing-whitespace trimming, max line length 240 (`.markdownlint-cli2.yaml`). In addition, write one sentence per line inside multi-sentence paragraphs: never cut a sentence, keep each sentence as short as possible, and start a new line right after the period that ends it. Single-sentence paragraphs/list items don't need to be split further.

## Tests

- `test/WebApi.UnitTests`: xunit v3 unit tests, e.g. AutoMapper configuration validation, the TV Time import parsers (`Import/Parsers/`, pure stream-in/records-out, no I/O beyond an in-memory stream), and `WatchNextService` (pure next-episode computation).
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
