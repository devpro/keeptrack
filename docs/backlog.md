# Backlog

## Code quality

- [ ] Bring the remaining code comments in line with the writing style in `AGENTS.md`, file by file when a file is touched rather than as one sweeping change: spaced hyphens used as dashes, and comments telling history ("used to", "no longer").
- [ ] Decide on the dashes and second person in UI copy (`— Choose an album —` placeholders, "Welcome back —", "across your shows"), which the writing rules cover for documentation but not explicitly for product text.
- [ ] Migrate the `WebApi/Import/` and `WebApi/ReferenceData/` feature folders to the layered shape: provider clients in their own folder, controllers in `Controllers/`, pure logic in `Domain/Services/` (`ReferenceMatchRules` and `RatingSourceCatalog` already are).

## Tests

- [ ] `StaleTokenRedirectSmokeTest.StaleFirebaseToken_On401_RedirectsToLogin_InsteadOfCrashingTheServerRender` failed once in a full parallel Playwright run on 2026-09-24 and passed twice alone.
  It only opens `/account/manage/shared/{id}`, so the failure is load-dependent: read its trace in `e2e-diagnostics` the next time it fails before raising any timeout.

## Dependencies

- [ ] `Verify.XunitV3` is held at 32.x: 33.x fails the build with `SC021` until a SponsorCheck license or exemption property is declared, which is the owner's decision.
- [ ] `SharpCompress` (pulled in by `MongoDB.Driver`) is pinned transitively at 0.50.x: 1.0 is a major version, adopted once the driver supports it.
