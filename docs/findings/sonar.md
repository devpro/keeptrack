# Sonar findings

What the SonarCloud analysis reported, which rules were acted on, and which are standing false positives that must not be "fixed".

## Standing analysis notes

1. S8970: null-forgiving operator (60 of 67 issues, MINOR)

    Verdict: false positive, don't touch the code.

    This rule fires when Sonar's engine believes nullable warnings are disabled at that point, making ! a no-op.
    But BlazorApp.csproj has `<Nullable>enable</Nullable>` project-wide, and every flagged ! (e.g. `context.User.Identity!.Name!` in Manage.razor:8, `(bool)e.Value!` in several @onchange handlers) is a genuine, meaningful suppression against a real nullable-annotated API (ClaimsPrincipal.Identity, ChangeEventArgs.Value).

    This is a known SonarC# limitation with Razor-generated code: the source generator's nullable-context pragmas don't map cleanly back onto markup-embedded lambdas/expressions, so Sonar loses track of the enclosing #nullable enable region.

    Removing these ! would just reintroduce real CS8600/CS8602 build warnings.

    Recommendation: bulk-resolve rule S8970 as "False Positive" in the SonarCloud UI rather than editing 60 call sites.

## Fixed

### Project-wide Sonar review (main branch, not PR-scoped): S2365, ASP0025 ×2, CA1862 ×2, CA1859 ×3, JS S2486

Fixed on 2026-07-27, reviewed against `https://sonarcloud.io/project/issues?issueStatuses=OPEN&id=devpro_keeptrack` (28 open issues at the time, excluding 3 `S1135` "TODO" issues out of scope for this pass).

- **S2365** CRITICAL, `PlaylistDetail.razor:144` - `PlaylistSongs` was a property doing `.Select().Where().ToList()` on every access, read twice per render (`.Count` then `@foreach`).
  Renamed to a method, `GetPlaylistSongs()`, per convention (expensive/allocating work shouldn't look like a cheap property).
  No behavior change.
- **ASP0025** INFO × 2, `WebApi/Program.cs`, `BlazorApp/Program.cs` - both used the older `AddAuthorization(options => { options.AddPolicy(...); ... })` shape;
  switched to `AddAuthorizationBuilder().AddPolicy(...).AddPolicy(...)`, the modern .NET 8+ API.
  Same policies, same behavior.
- **CA1862** INFO × 2, `AlbumReferenceRepositoryTest.cs:103`, `BookReferenceRepositoryTest.cs:144` - test assertions did `m.Title == title.ToLowerInvariant()`; switched to `string.Equals(m.Title, title, StringComparison.OrdinalIgnoreCase)`.
- **CA1859** INFO × 3 - `AmazonOrderPreviewServiceTest.ToStream`/`GenericVideoGameImportServiceTest.ToStream` now return `MemoryStream` instead of `Stream`;
  `OpenLibraryClientTest.BuildClient` now returns `OpenLibraryClient` instead of `IBookReferenceClient` (checked call sites first - both members it exposes, `ProviderKey`/`GetBookDetailsAsync`, are public on the concrete class, not explicit interface implementations).
- **javascript S2486** MINOR, `ReconnectModal.razor.js:42` - `catch (err)` never used `err`, silently swallowing the exception.
  Added `console.error("Blazor reconnect failed:", err)`.

Investigated but confirmed **not** actionable during the same pass (left as-is, see "Sonar issues" note below for the rest of the 28):
`S8969` in `TvTimeImportService.cs:469-470` looked like the same Razor-generated-code false positive as `S8970` above, but is a **different, real** finding - removing the `!` after `Dictionary<TKey,TModel>.TryGetValue`'s `out model!` reintroduces genuine `CS8601` warnings on rebuild (confirmed by actually removing it and rebuilding), because `[MaybeNullWhen(false)]` doesn't flow cleanly through the open generic `TModel` parameter here.
Don't conflate the two rule ids - `S8970` (Razor markup, nullable context lost) is a false positive; `S8969` (plain `.cs`, "the compiler already knows") needs checking case-by-case, this one isn't.

Verification: full solution build (0 warnings/errors), full `WebApi.UnitTests` run (235/235 passed, includes the three CA1859-touched test classes).
Once a local MongoDB became available, also ran directly against it (`Local.runsettings` env vars loaded into the process, real Firebase auth):
`AlbumReferenceRepositoryTest`/`BookReferenceRepositoryTest` (the two `CA1862` files) - 7/7 passed;
`ReferenceDataAdminResourceTest` (real HTTP call through `[Authorize(Policy="AdminOnly")]`) plus `PlaylistResourceTest`/`BookResourceTest` (real HTTP calls through `[Authorize(Policy="MemberOnly")]`) - 9/9 passed (1 self-skipped, the opt-in `SyncNow_PollingReachesACompletedResult`) - this is what actually proves the `ASP0025` `AddAuthorizationBuilder` switch still enforces both policies correctly end-to-end, not just that the attribute is present;
`BlazorApp.PlaywrightTests`' `PlaylistSmokeTest.AddAndDelete_PlaylistThroughTheList` (real browser, real Blazor Server circuit) - passed, proving `GetPlaylistSongs()` renders correctly post-rename.
That Playwright test still only exercises `GetPlaylistSongs()`'s empty-list branch (no song is ever added to the playlist in that test) - the populated-list/dangling-`SongId`-skip branch has no automated coverage before or after this change; adding it would need a synthetic album+tracklist fixture (a bigger addition than the rename itself), flagged here rather than silently left uncovered.

Files: `src/BlazorApp/Components/Inventory/Pages/PlaylistDetail.razor`, `src/WebApi/Program.cs`, `src/BlazorApp/Program.cs`, `test/WebApi.IntegrationTests/Resources/AlbumReferenceRepositoryTest.cs`, `test/WebApi.IntegrationTests/Resources/BookReferenceRepositoryTest.cs`, `test/WebApi.UnitTests/Services/AmazonOrderPreviewServiceTest.cs`, `test/WebApi.UnitTests/Services/GenericVideoGameImportServiceTest.cs`, `test/WebApi.UnitTests/ReferenceData/OpenLibraryClientTest.cs`, `src/BlazorApp/Components/Layout/ReconnectModal.razor.js`

### S107: too many parameters on `OwnedItemImportMergeService.ComputeCommitPlan`/`.MergeItem` and `AmazonImportController.CommitAsync`

Fixed on 2026-07-26 (PR #467 Sonar review).
All three methods carried the same six-delegate bundle (`getExistingTitle`, `getExistingReferences`, `getItemTitle`, `getItemReference`, `createNew`, `appendOwnedCopy`) as separate parameters, pushing their signatures to 8/9/10 params.
This was the intentional "generic engine over delegates instead of an interface" design (still documented in CLAUDE.md), so the fix keeps that design - it just stops repeating the six delegates individually.
Bundled them into one new `OwnedItemImportAdapter<TModel, TRequestItem>` record (`Domain/Models/OwnedItemImportAdapter.cs`) and threaded that single value through instead, cutting `ComputeCommitPlan` to 3 params, `MergeItem` to 6, and `CommitAsync` to 5 - no change in behavior or genericity, all 8 call sites (6 in `AmazonImportController`, 1 in `GenericVideoGameImportController`, 2 in `OwnedItemImportMergeServiceTest`) construct the adapter inline the same way they used to pass the delegates.

Files: `src/Domain/Models/OwnedItemImportAdapter.cs`, `src/Domain/Services/OwnedItemImportMergeService.cs`, `src/WebApi/Controllers/AmazonImportController.cs`, `src/WebApi/Controllers/GenericVideoGameImportController.cs`, `test/WebApi.UnitTests/Services/OwnedItemImportMergeServiceTest.cs`
