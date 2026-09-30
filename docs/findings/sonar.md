# Sonar findings

Which SonarCloud rules are standing false positives that must not be "fixed", and which fixes carry a reason worth keeping.

## S8970 in Razor is a false positive

Sonar loses the nullable context in Razor-generated code, so it reports every `!` in markup as useless (60 of 67 issues).
`BlazorApp` has nullable enabled project-wide and each `!` suppresses a real nullable API (`ClaimsPrincipal.Identity`, `ChangeEventArgs.Value`), so removing one brings back `CS8600`/`CS8602`.
They are to be bulk-resolved as False Positive in SonarCloud rather than edited.

## S8969 is checked case by case

It looks like S8970 but applies to plain `.cs`, and it can be real.
The `!` in `TvTimeImportService.cs` stays: removing it reintroduces `CS8601`, since `[MaybeNullWhen(false)]` doesn't flow through the open generic `TModel`.

## The import merge takes one adapter, not six delegates (S107)

`OwnedItemImportMergeService` and the import controllers pass `OwnedItemImportAdapter<TModel, TRequestItem>` rather than six separate delegates.
It keeps the generic-engine-over-delegates design while fixing the parameter count.

## Authorization uses `AddAuthorizationBuilder` (ASP0025)

Both `Program.cs` register policies with `AddAuthorizationBuilder().AddPolicy(...)`.
The `AdminOnly`/`MemberOnly` resource tests are what prove the policies are still enforced.

## Known coverage gap

`PlaylistSmokeTest` covers only an empty playlist, so the populated branch of `PlaylistDetail`'s `GetPlaylistSongs()` has no automated test.
