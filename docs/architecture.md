# Architecture

Three tiers: a Blazor Server UI (`BlazorApp`), a REST API (`WebApi`) and MongoDB.
The UI only talks to the API over HTTP, and the API alone reads and writes the database.

## Projects

Layered architecture across small single-purpose projects in `src/`, with `Domain` at the center and nothing referencing outward.

- **`Common.System`**, depending on nothing: cross-cutting primitives (`IHasId`, `IHasIdAndOwnerId`, `PagedRequest`, `PagedResult<T>`, `TitleNormalizer`, `ListSort`, `RefuelCostCheck`).
- **`Domain`**, depending on `Common.System`: business models (`Models/*Model`), repository interfaces (`Repositories/I*Repository`) and pure services (`Services/`), with no persistence or web concerns.
- **`Infrastructure.MongoDb`**, depending on `Domain`: BSON `Entities/`, `Repositories/`, `Mappers/`.
- **`WebApi.Contracts`**, depending on `Common.System`: the public REST DTOs (`Dto/`), shared with `BlazorApp` so the client deserializes without duplicate classes.
- **`WebApi`**, depending on `Infrastructure.MongoDb`, `Domain` and `WebApi.Contracts`: controllers, DTO mappers, DI, JWT auth, OpenAPI/Scalar.
- **`BlazorApp`**, depending on `Common.System` and `WebApi.Contracts`: the Blazor Server UI over HTTP, never referencing `Domain` or `Infrastructure.MongoDb`.

Controllers live in `WebApi/Controllers/`, with any real computation in `Domain/Services/`.
`WebApi/Import/` and `WebApi/ReferenceData/` use an older feature-folder shape that new code does not extend (see [backlog](backlog.md)).

The data conventions shared by every layer are in [Data model](data-model.md).

## Request flow

`DataCrudControllerBase<TDto, TModel>` implements the whole CRUD surface once.
It reads the caller's `user_id` claim through `ControllerBaseExtensions.GetUserId()` to scope every query and stamp `OwnerId`, and every controller uses that extension rather than re-reading the claim.
A per-type controller is a one-line class extending it, and CRUD logic is never duplicated per controller.

Read-only cross-entity aggregations (`WatchNextController`, `WishlistController`, `StatsController`, `SystemStatusController`) are plain `ControllerBase` classes.

**A record update never changes a reference link** (`DataCrudControllerBase.PreserveServerOwnedFieldsAsync`, over `IReferenceLinkedModel`).
A PUT is a full replace, and a detail page opened before background resolution holds a copy with an empty `ReferenceId`, so its first edit would erase the link.
The link and its rating fields are restored from storage on every update, the same way `OwnerId` is protected.
Resolution, the detail page's check and an admin unlink write the link through a repository, never through the CRUD controller.

## Errors

`ApiExceptionFilterAttribute` logs every unhandled exception, then converts it: `ArgumentException` to 400, a failed provider call to 502, anything else to 500.

- **A provider that timed out, exhausted its retries or tripped its circuit breaker is a 502, never a 500** (`TimeoutRejectedException`, `BrokenCircuitException`, `HttpRequestException`, logged as a warning).
  A 500 would blame this API for a provider outage.
- **The 502's `{ error }` says what the provider did** (`DescribeUpstreamFailure`: its status, unreachable, timed out or circuit open).
- **`BlazorApp/Components/Shared/ApiResponseExtensions` (`EnsureSuccessOrThrowAsync`, `ReadJsonOrThrowAsync`) is used wherever a failure is shown to a user**, never `EnsureSuccessStatusCode` or `GetFromJsonAsync`, which discard the body and leave the user with "502 Bad Gateway".
  They throw `ApiRequestException`, whose `IsUpstreamProviderFailure` tells a provider outage from a defect.
  `InlineReferenceLinker` then names the provider, quotes the detail, and points at the provider picker when the domain has more than one.

A missing item is a 404 at every layer, never the error page: see [Blazor UI](blazor-ui.md#missing-pages-and-missing-items).

## Outbound calls

Every third-party client chains `.AddStandardResilienceHandler()` on its `AddHttpClient<...>()` registration, a new one included, never a hand-rolled retry (`ExternalProviderResilienceTest`).
Provider specifics are in [Providers](providers.md).

## Background work

**Long-running work runs as a background job, never a blocking request**: buffer the input, start the work on a fresh `IServiceScopeFactory.CreateScope()`, return a job id, poll its status.
`JobStore<TStage, TResult>` (`WebApi/Jobs/`) is backed by MongoDB (`background_job`, TTL 7 days), since the replica answering a poll is not necessarily the one running the job.
The owner id is checked in the repository query on every read, and a background task resolves its own `JobStore` from its own scope.

**A detached job runs on `IHostApplicationLifetime.ApplicationStopping`, never an unbounded token.**
On shutdown it would otherwise keep working against disposed singletons (Mongo client, HTTP clients, IGDB's rate limiter), every step would throw `ObjectDisposedException`, and the job would read "Running" forever.
For the same reason, per-item catches that keep one failing document from aborting a run (`ReferenceSyncService`, `ExploreCatalogueRefreshService`) exclude `OperationCanceledException`.

`HostOptions.BackgroundServiceExceptionBehavior = Ignore` in `Program.cs` is a backstop, since by default an exception escaping any `BackgroundService` stops the entire host.
A background service still catches what it can anticipate.

**A request timeout leaves no trace in the WebApi logs**, since `"Microsoft": "Warning"` hides request start and finish.

`CancellationToken` passing is incomplete: see [backlog](backlog.md#cancellation).

## Authentication and authorization

- Firebase authenticates: a cookie in `BlazorApp`, a JWT bearer validated against Firebase in `WebApi`, and `AuthenticationTokenHandler` attaches the bearer to outgoing API calls.
- Authorization is policy based: `AdminOnly` is `RequireClaim("role", "admin")` and `MemberOnly` is `RequireClaim("role", "member", "admin")`, registered with `AddAuthorizationBuilder()` in both `Program.cs` files.
  Firebase sends a plain `role` claim, which `BlazorApp`'s `AuthenticationController` copies into the cookie principal at sign-in (`FirebaseClaimsBuilder`).
- **Gotcha: `AddJwtBearer` sets `MapInboundClaims = false`**, otherwise the handler renames short JWT claim names to legacy `ClaimTypes.*` URIs and `RequireClaim("role", ...)` never matches.
  A new custom claim is checked against this, and it is also what keeps the `email` claim readable for [collection sharing](sharing.md).

### Free preview tier

An account with no `role` claim gets movies and TV shows only, capped at `Features:FreeTierItemLimit` per collection (default 20, `AppConfiguration.GetFreeTierItemLimit`).
Episodes are capped at 100 times that (`EpisodeController.FreeTierLimitFactor`), only to stop a raw API caller flooding the database.

Enforcement is API side: `[Authorize(Policy = "MemberOnly")]` on every restricted controller, plus the creation quota in `FreeTierQuota.CheckAsync`, called by `DataCrudControllerBase.Post` and by every other path that creates an item (403 with `{ error }`).
`NavMenu.razor` hiding sections is UX, never security, and `FreeTierTest` carries a reflection guard asserting each controller's expected policy.

### Admin settings

Runtime-changeable global settings live in one `app_setting` document (`_id: "global"`, one field per setting) through `IAppSettingRepository`, written with a targeted `$set`.
A new setting is a new field there, never a new collection.
Deploy-time values stay in `AppConfiguration` and environment variables, since those cannot change without a redeploy.

## Scaling

Scaling is designed in, never assumed, since the app may sit behind a Cloudflare tunnel with no sticky sessions.

- `DataProtection:MongoDb:*` persists the key ring (`DataProtection/MongoDbXmlRepository`) so cookies decrypt on every replica, the only reason `BlazorApp.csproj` references `MongoDB.Driver`.
- `Features:IsWebSocketsOnlyEnabled` (default `true`) pins a circuit to its pod, and is set `false` only behind a proxy without WebSockets, with a single replica.
- Background jobs are stored in MongoDB, and the reference sync takes a lease (see [Reference data](reference-data.md#keeping-references-fresh)).
