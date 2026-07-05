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

### Web API request flow

`DataCrudControllerBase<TDto, TModel>` (`WebApi/Controllers/DataCrudControllerBase.cs`) implements the full CRUD surface (`GET`, `GET/{id}`, `POST`, `PUT/{id}`, `DELETE/{id}`) once, generically. It reads the caller's `user_id` claim to scope every query and to stamp `OwnerId` on writes, so per-type controllers only need routing and generic type arguments. Unhandled exceptions are converted to JSON error responses by `ApiExceptionFilterAttribute` (`ArgumentException`/`ArgumentNullException` -> 400, everything else -> 500).

### Blazor app

`InventoryPageBase<TDto>` (`BlazorApp/Components/Inventory/InventoryPageBase.cs`) centralizes list/paging/search/inline-edit state and calls into `InventoryApiClientBase<TDto>`, which wraps the typed `HttpClient` calls to the Web API. Each concrete page (`Books.razor.cs`, `Movies.razor.cs`, ...) only supplies its `Api` instance and `CloneItem`. Authentication uses Firebase (cookie auth in the Blazor app, JWT bearer validated against Firebase in the Web API); `AuthenticationTokenHandler` attaches the bearer token to outgoing API calls.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C#/Razor, LF line endings, `var` preferred everywhere, braces required, `_camelCase` for private instance fields, `s_camelCase` for private static fields, PascalCase for everything else. Avoid `this.` qualification.
- Primary constructors are the norm for controllers, repositories and API clients (see `BookController`, `BookRepository`, `BookApiClient` above).
- Nullable reference types are enabled across all `src` projects; use `required` for non-nullable properties that have no sensible default (e.g. `BookModel.Title`).
- Public WebApi.Contracts DTOs and WebApi controllers carry XML doc comments (`GenerateDocumentationFile` is enabled) because they feed the generated OpenAPI/Scalar documentation.
- Markdown files: 2-space indent, no trailing-whitespace trimming, max line length 240 (`.markdownlint-cli2.yaml`). In addition, write one sentence per line inside multi-sentence paragraphs: never cut a sentence, keep each sentence as short as possible, and start a new line right after the period that ends it. Single-sentence paragraphs/list items don't need to be split further.

## Tests

- `test/WebApi.UnitTests`: xunit v3 unit tests, e.g. AutoMapper configuration validation.
- `test/WebApi.IntegrationTests`: xunit v3 tests booted against a real Kestrel host (`KestrelWebAppFactory<Program>`) and a real MongoDB instance. `ResourceTestBase` provides typed `GetAsync`/`PostAsync`/`PutAsync`/`DeleteAsync` helpers and an `Authenticate()` helper that logs in against Firebase to obtain a bearer token. Resource tests (`BookResourceTest`, `MovieResourceTest`) exercise a full create/read/update/delete cycle against the live API and clean up what they create.
- Assertions use `AwesomeAssertions` (a `FluentAssertions`-compatible API); test data is generated with `Bogus`.

## CI

GitHub Actions (`.github/workflows/ci.yaml`) runs, on push/PR to `main`: a git/markup lint job, a .NET quality job (build, test with coverage, SonarCloud, FOSSA license/security scan) gated on app changes, and a container image scan for both Dockerfiles. Equivalent pipelines exist for GitLab CI and Azure DevOps.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms. Hold every change to this standard, not just new code.

- No duplicated algorithms or logic. Duplicated data shapes (a `Model`, an `Entity`, and a `Dto` that mirror the same fields) are fine and expected; duplicating the logic that operates on them is not. If two repositories, controllers, or components need the same behavior, it belongs in a shared base class or method, following the existing `DataCrudControllerBase<TDto, TModel>` / `MongoDbRepositoryBase<TModel, TEntity>` / `InventoryPageBase<TDto>` pattern.
- Every non-trivial piece of logic needs a test, especially per-type overrides like `GetFilter`. These are the most duplicated, least-reused pieces of code in the solution, and history has already shown they are where bugs hide (see `docs/code-quality-findings.md`).
- Before proposing a fix, verify the current best-practice for the specific library/framework version in use (e.g. MongoDB driver filter semantics, current ASP.NET Core guidance) rather than relying on older patterns from training data.
- Known findings from past reviews, including which items are confirmed bugs versus intentional by-design behavior, are tracked in `docs/code-quality-findings.md`. Check it before re-reporting something already triaged there, and update it when a listed item is fixed.
