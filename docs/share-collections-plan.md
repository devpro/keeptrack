# Share collections with other Keeptrack users

## Context

Keeptrack today is strictly single-tenant: every query is scoped to the caller's `user_id` claim, and the only
cross-user sharing is the **anonymous wishlist link** (`WishlistController`, capability token, `[AllowAnonymous]`).

The owner wants to share **whole categories** of their data with **specific family/friends who have Keeptrack
accounts**, read-only:

- **Media** (movies, TV shows, books, albums, video games, …): read-only view, plus an "Add to my collection"
  action that copies the item's identity into the recipient's own collection (no owned-copy element).
- **Personal / sensitive** (cars, houses, health): read-only view, **no copy**, and health is the strictest case.

Two decisions already confirmed with the owner:
1. **Granularity = by whole category** (no per-item picker).
2. **Recipient = by account email** (a directed grant, not a capability link — nothing sensitive rides in a URL).

The enabling fact: the repository layer already takes `ownerId` as a **plain parameter**
(`IDataRepository.FindAllAsync(ownerId, …)`, `FindOneAsync(id, ownerId)`), so reading another owner's data is a
controller/authorization concern only — no Mongo query changes needed. `WebApi/Program.cs` sets
`MapInboundClaims = false`, so the Firebase `email` claim is readable verbatim on `HttpContext.User`.

## Architecture (decided)

**The grant** — a new `share` collection, one document per (owner → recipient) grant:

```
ShareModel : IHasId
  Id
  OwnerId               // sharer (the creating user's user_id)
  OwnerDisplayName      // denormalized from the creator's "name"/"email" claim, for recipient-side display
  RecipientEmail        // normalized lowercase — the friend's account email
  IncludedCategories    // List<ShareCategory>  (Movies, TvShows, Books, Albums, VideoGames, Cars, Houses, Health, …)
  Label                 // owner-only bookkeeping, like WishlistShareModel.Label
  CreatedAt
```

- **No stored `Kind`.** Media-vs-Personal is derived from the category by a single static classifier
  (`ShareCategory` → `Media | Personal`) in a Domain service, so the "is this copyable / is this sensitive"
  rule lives in exactly one place. Health is its own category and never auto-included by a "select all".
- Indexes (`scripts/mongodb-create-index.js`, mirror the `wishlist_share` block): `share_owner` on `owner_id`,
  and `share_recipient` on `recipient_email` (the recipient's lookup key).

**Recipient views = dedicated read-only pages, NOT retrofitted editable pages.** The ~12 detail pages
(`MovieDetail.razor`, etc.) are bespoke, auto-save on every field change, and are dense with
`[PersistentState]`/prerender logic — threading a read-only mode through all of them (plus their API clients)
is invasive and high-risk. The established precedent is `SharedWishlistPage.razor`: a *separate*, lean,
read-only page that reuses the presentational sub-components (`ItemThumb`, `ItemGridCard`, `CastGrid`,
`WishlistRow`) rather than reusing the editable page. We follow that precedent. (Unlike SharedWishlist, these
pages are **authenticated**, so their API client uses the normal `AuthenticationTokenHandler` registration.)

**Read path (server).** A `SharedWithMeController` (`[Authorize]`, any authenticated user — recipients may be
free-tier) that, for every read:
1. loads the grant by id, **verifies `RecipientEmail == caller email`** (server-side, never trust the id alone),
2. verifies the requested category is in `IncludedCategories`,
3. reads via the existing repository with `share.OwnerId` as the scope, maps with the existing DTO mapper, and
   hydrates cover images exactly like `WishlistController.BuildWishlistAsync` does
   (`ReferenceImageHydrator.HydrateAsync`).

To avoid per-type duplication, extract a small generic helper
`ReadSharedPageAsync<TModel,TDto>(ownerId, repo, mapper, hydrator, paging)` and call it per category — the
controller injects the repositories/mappers the same way `WishlistController` already does.

**Copy (media only).** `POST /api/shared-with-me/{shareId}/{category}/{itemId}/copy` →
verify grant + category is **Media** + category in scope, `FindOneAsync(itemId, share.OwnerId)`, build a fresh
model carrying **only identity + reference link** (`Title`, `Year`, `ReferenceId`, creator fields where they
exist), stamp caller as `OwnerId`, drop owned copies / rating / favorite / notes / dates, `CreateAsync`. Keeping
`ReferenceId` means the copy is instantly cover-art/synopsis-linked (reference data is owner-less/shared). The
per-type "strip to identity" factory lives in a Domain service (`SharedItemCopyService`), mirroring the
model-construction delegates in `OwnedItemImportCommitCoordinator`. **The copy must re-apply the free-tier
quota** (extract the check from `DataCrudControllerBase.Post` into a reusable helper) so a free-tier recipient
copying a Movie/TvShow hits the same limit as a direct create.

## Phasing (reviewable slices)

- **Phase 1 — Foundation + media loop end-to-end.** Grant model→entity→repo→mapper→DTO + indexes + DI;
  `ShareController` (owner CRUD of grants); `SharedWithMeController` read + copy for the **media** categories;
  owner "Sharing" page; recipient "Shared with me" page (read-only list/grid reusing `WishlistRow`/`ItemThumb`)
  with per-item "Add to my collection". Delivers the whole friend-facing loop.
- **Phase 2 — Personal / sensitive read views.** Car (+ history log), House (+ history), Health (records) as
  dedicated **read-only detail** pages (a bare list isn't useful for these — the value is the detail). Health
  gets an explicit "you are sharing your health journal with `<email>`" confirmation on the owner side.
- **Phase 3 (optional, later).** Read-only *detail* pages for media (cover/synopsis/cast) if the list-level
  view proves insufficient.

## Detailed changes

### Domain (`src/Domain`)
- `Models/ShareModel.cs`, `Models/ShareCategory.cs` (enum), `Repositories/IShareRepository.cs`
  (`FindAllByOwnerIdAsync(ownerId)`, `FindAllByRecipientEmailAsync(email)`, `FindByIdAsync(id)`,
  `CreateAsync`, `DeleteAsync(id, ownerId)` — model on `WishlistShareRepository`).
- `Services/ShareCategoryClassifier.cs` (category → Media/Personal; the one place that rule lives) and
  `Services/SharedItemCopyService.cs` (per-media-type identity-only copy factory). Both `AddSingleton`,
  unit-tested — same shape as `WatchNextService`.

### Infrastructure (`src/Infrastructure.MongoDb`)
- `Entities/Share.cs` (`[BsonElement]` snake_case, model on `WishlistShare.cs`),
  `Repositories/ShareRepository.cs`, `Mappers/ShareStorageMapper.cs`
  (`IStorageMapper<ShareModel, Share>`). `ShareCategory` list reuses the Domain enum directly (Infra depends on
  Domain), with `EnumRepresentationConvention` already registered.

### WebApi (`src/WebApi`)
- Register repo + mapper in `DependencyInjection/InfrastructureServiceCollectionExtensions.cs`
  (`AddSingleton<ShareStorageMapper>()`, `TryAddScoped<IShareRepository, ShareRepository>()`).
- `Controllers/ControllerBaseExtensions.cs`: add `GetEmail()` (reads the `"email"` claim; throws
  `UnauthorizedAccessException` when absent).
- `Controllers/ShareController.cs` (`[Authorize]`, `api/shares`): GET/POST/DELETE owner grants; POST stamps
  `OwnerId`/`OwnerDisplayName` from claims and normalizes `RecipientEmail`.
- `Controllers/SharedWithMeController.cs` (`[Authorize]`, `api/shared-with-me`): `GET /` (grants for caller
  email → `SharedCollectionSummaryDto` list), `GET /{shareId}/{category}` (paged read via the shared helper),
  `POST /{shareId}/{category}/{itemId}/copy`. Extract the map+hydrate read helper here (or a shared static),
  and extract the free-tier quota check out of `DataCrudControllerBase.Post` so both the create path and the
  copy path call it.
- `Mappers/ShareDtoMapper.cs` (`IDtoMapper<ShareDto, ShareModel>`, registered in `Program.cs` with
  `EnumMappingStrategy.ByName` for the category enum), plus the read-only Model→Dto mapper for the recipient
  summary (model on the `WatchNext`/`Wishlist` one-directional mappers).

### Contracts (`src/WebApi.Contracts`)
- `Dto/ShareDto.cs`, `CreateShareRequestDto` (RecipientEmail + IncludedCategories + optional Label),
  `SharedCollectionSummaryDto` (owner display name, label, categories, share id), and a **duplicate**
  `ShareCategory` enum here (Contracts can't reference Domain — same split as every other DTO/Domain enum,
  member names identical, mapped `ByName`).

### Blazor (`src/BlazorApp`)
- Clients in a new `Components/Sharing/` folder: `ShareApiClient` (owner grants) and `SharedWithMeApiClient`
  (recipient reads + copy), both registered in `DependencyInjection/InfrastructureServiceCollectionExtensions.cs`
  **with** auth (default `AddHttpClient<>` there already attaches the token handler — unlike `SharedWishlist`).
- `Pages/SharingPage.razor` (`/sharing`, owner side): create grant (recipient email + category checkboxes
  grouped Media / Personal; Health checkbox carries a confirm), list + revoke grants. Model the share-panel
  markup on `WishlistPage.razor`'s existing share UI.
- `Pages/SharedWithMePage.razor` (`/shared-with-me`, recipient side): list sharers/categories; opening a
  category shows a read-only list/grid (reuse `WishlistRow` + `ItemThumb`/`ItemGridCard`) with an "Add to my
  collection" button per media row.
- `NavMenu.razor`: add "Sharing" and "Shared with me" links (both inside the authenticated block; available to
  all authenticated users, not gated to MemberOnly — recipients may be free-tier).
- Phase 2 adds `Components/Sharing/` read-only detail pages for Car/House/Health reusing their existing
  read-only sub-components (history rows, records table, `SvgChartHelpers` charts).

### Scripts
- `scripts/mongodb-create-index.js`: add the two `share` indexes next to the `wishlist_share` block.

### Tests (per the quality bar — a test at each layer)
- Unit: `ShareCategoryClassifierTest`, `SharedItemCopyServiceTest` (identity-only copy drops owned/rating/notes,
  keeps ReferenceId).
- Integration (`KestrelWebAppFactory`, model on `WishlistShareResourceTest`): `ShareResourceTest` — owner
  create/list/revoke; a **second authenticated HttpClient** as the recipient reading the shared category and
  copying a media item; assert a non-recipient email gets nothing; assert category-not-in-scope is refused;
  assert the free-tier quota still applies to copies (the integration user is admin, so cover the quota in a
  unit test like `FreeTierTest` does).
- Playwright (`E2E_ENABLED`): a `SharingSmokeTest` — owner shares a category, recipient (the same fixture user,
  sharing to their own email) sees it read-only and copies one item. Add `data-testid`s only where
  `GetByLabel` can't resolve, per the existing convention.

## Security & edge cases
- Recipient match is **server-side by email on every read/copy** — the share id alone never grants access.
- Emails normalized lowercase on both store and match. A recipient whose provider yields **no `email` claim**
  (e.g. a GitHub account with a private email) can't be matched — documented limitation; the owner shares to
  the email the friend actually signs in with.
- Copy re-validates `Kind == Media` and scope server-side, and enforces the free-tier quota.
- Health is opt-in per grant, never bundled, with an owner-side confirmation.
- Revoking = delete one owner-scoped document; the recipient's next read returns nothing.

## Verification
- `dotnet build` then `dotnet test` (unit + integration; integration needs local MongoDB + Firebase test creds
  per CONTRIBUTING.md).
- Manual: run WebApi + BlazorApp, sign in, create a grant to a second account's email, sign in as that account,
  confirm the shared category is visible read-only, "Add to my collection" creates a reference-linked copy with
  no owned versions, and revoking removes access.
- Re-run the Playwright `SharingSmokeTest` (and `MobileScreenshotTest` for the two new pages) with `E2E_ENABLED=true`.

## Progress log — post-review rework (current)

The owner reviewed the first cut and it was reworked (see `.claude/plans/vectorized-bubbling-shore.md` for the
detailed revision plan). Done and building clean:
- **Members-only**: both `ShareController` + `SharedWithMeController` are `[Authorize(Policy="MemberOnly")]`
  (free tier can't share or view shared content); `FreeTierTest` guards this.
- **Under the profile, not the nav**: sharing lives at `/account/manage/sharing`,
  `/account/manage/shared-with-me`, `/account/manage/shared/{shareId}`; the profile nav item is a
  prefix-matching `NavLink` so it stays current; `Breadcrumb` gained an optional parent crumb
  (`Profile › Shared with me › <owner>`).
- **Full-featured read-only lists**: shared categories render via the real `InventoryList` (new `ReadOnly` +
  `RowActions` + `EmptyText`), with search / rating-sort / favourites+owned filters / thumbnails / grid. Per-type
  meta extracted to `Components/Inventory/Meta/*MetaRow.razor`, reused by owner pages and the shared view.
- **Shared-with-me picks the person** → opens their collection with category tabs (tab persisted in `?tab=`).
- **Add = SVG icon + tooltip** (`AddToCollectionIcon`), with a spinner and an "In collection" badge.
- **Dedup-safe add**: `SharedItemMatcher` (reuses `TitleNormalizer`) makes copy idempotent and annotates each
  read page with `AlreadyInCollectionIds`. Covered by `SharedItemMatcherTest` + `ShareResourceTest`.
- **Fixed after owner UI review**: the shared list's `Search`/`Sort`/`View` were binding literal strings
  (the CLAUDE.md `@`-prefix gotcha) — now `@`-prefixed; tab now persists in the URL.

Still deferred: Playwright `SharingSmokeTest` (WSL E2E env); Phase 2 personal (car/house/health) read views.

## Progress log — Phase 1 (superseded by the rework above)

- **Phase 1: DONE (not committed).** Full media loop implemented and green at every layer:
  - Domain: `ShareModel`, `ShareCategory`, `ShareKind`, `IShareRepository`, `ShareCategoryClassifier`, `SharedItemCopyService`.
  - Infrastructure: `Share` entity, `ShareStorageMapper`, `ShareRepository`, DI + two `share` indexes in `scripts/mongodb-create-index.js`.
  - Contracts: `ShareDto`/`CreateShareRequestDto`/`SharedCollectionSummaryDto` + duplicate `ShareCategory` enum.
  - WebApi: `GetEmail()`/`GetDisplayName()` extensions, extracted `FreeTierQuota` helper (reused by CRUD create + copy),
    `ShareDtoMapper`, `ShareController` (owner CRUD), `SharedWithMeController` (recipient read + media copy for Movies/TvShows/Books/Albums/VideoGames).
  - Blazor: `ShareApiClient`, `SharedWithMeApiClient`, `SharingPage.razor` (`/sharing`), `SharedWithMePage.razor` (`/shared-with-me`),
    `WishlistRow.FromAlbums`, two NavMenu links, DI registration.
  - Tests: `ShareCategoryClassifierTest` (8) + `SharedItemCopyServiceTest` (4) + `FreeTierTest` policy rows (26 total) — all pass;
    `ShareResourceTest` (3) — passes against real MongoDB + Firebase. Whole solution builds with 0 warnings.
  - **Deferred within Phase 1:** the Playwright `SharingSmokeTest` was not written yet (runs in the user's WSL E2E env).
- **Phase 2 (not started):** personal/sensitive read-only detail views for Cars/Houses/Health + owner-side health confirmation.
  The `ShareCategory` enum + classifier already include `Cars`/`Houses`/`Health`; the owner UI currently offers media categories only.

### Note for the runner
`dotnet test` reported "zero tests ran" in this environment; run the built MTP exe directly instead, e.g.
`test/WebApi.UnitTests/bin/Debug/net10.0/Keeptrack.WebApi.UnitTests.exe --filter-query "/*/*/ShareResourceTest/*"`.
Integration tests need `FIREBASE_APIKEY`/`FIREBASE_USERNAME`/`FIREBASE_PASSWORD` env vars (from `Local.runsettings`) and a local MongoDB.
