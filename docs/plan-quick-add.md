# Plan to implement "Quick Add — one-tap capture of any entry"

## Context

Recording something new today means navigating to the right list page (or the right parent detail page for car/house/health records) an using that page's own add form/modal —
several taps through a collapsed sidebar on mobile, the primary adoption surface.
The goal: a single "Quick Add" entry point (nav item below Home + Home page button) opening a mobile-first form where the user picks a type,
fills one all-in-one form (including an optional owned copy for media), saves, and lands on the created item's detail page (parent's detail page for records) to review/check reference/refine.

Decisions confirmed with the owner:

- 8 types: Movie, TV show, Book, Video game, Album, Car record, House record, Health record (Playlist out).
- Owned copy = for media items (movie, tv show, book, video game, album) collapsed "I own a copy" toggle revealing the copy fields; for games the platform entry is the copy.
- After save: item detail page (media) / parent detail page (records).

## Design summary

 A new routable page `/add` in a `Components/QuickAdd/` feature folder (WatchNext-style: own layout on kt-* classes, not `InventoryPageBase` — so the record DTOs' required members cause no new() constraint problem).
 The selected type lives in the URL (`/add?type=movie`) via `[SupplyParameterFromQuery]`, per the app's URL-state convention — back button returns from form to picker, deep links work.
 No WebApi/Domain changes: everything goes through the existing DI-registered API clients; `InventoryApiClientBase.AddAsync` already surfaces the free-tier quota 403 `{error}` text as an exception, and media controllers' `OnCreatedAsync` auto-enrichment fires for free on quick-added items.

 Three extraction refactors come first — they remove exactly the duplication Quick Add would otherwise copy (the CLAUDE.md zero-duplication bar):

 1. `DateTimeFields` — the ModalDate/ModalTimeText DateOnly+"HH:mm" proxy pair exists twice today (CarDetail.razor ~344-366, HealthProfileDetail.razor ~295-312).
 2. `CarHistoryForm/HouseHistoryForm/HealthRecordForm` — the three record modal form bodies become shared components used by both the detail-page modals and Quick Add.
 3. `IOwnedCopyDto` + `OwnedVersionFields` — the per-copy fields are already duplicated between OwnedVersionsEditor.razor and VideoGameDetail.razor's platform cards;
    one shared component fixes that existing duplication and serves Quick Add too.

## Implementation steps (each independently reviewable)

1. `DateTimeFields` extraction (pure refactor)

    New `src/BlazorApp/Components/Shared/DateTimeFields.razor`:
    the Date `<input type="date">` + free-text "HH:mm" Time input pair, with the tw proxy properties (`TimeOnly.TryParseExact("HH:mm", InvariantCulture)`) moved in verbatim, keeping both doc comments (why a proxy pair; why not `<input type="time">`).

    Parameters: `DateTime Value` + `EventCallback<DateTime>` `ValueChanged` (callers use @bind-Value).
    Standardize on one column-width pair (Car uses col-md-3/3, Health col-md-4/3 — negligible visual diff).

    Rewire `CarDetail.razor` and `HealthProfileDetail.razor`; delete the local pairs.

2. `CarHistoryForm` extraction

    New `src/BlazorApp/Components/Inventory/Shared/CarHistoryForm.razor` — params required `CarHistoryDto` Entry, bool `ShowFuel`, bool `ShowElectric` (flags stay computed by the caller from `CarDto.EnergyType`).
    Body = the entire row g-3 from CarDetail's modal (~195-293): DateTimeFields, Mileage, ΔMileage, CarHistoryType button group, refuel-gated fuel/electric/station/full-refill block, Garage else-branch, location, coordinates, Cost, Description.
    public static CarHistoryDto NewEntry(string carId) (CarId, HistoryDate = DateTime.Now, EventType = Refuel) moves here so the defaults exist once.
    CarDetail keeps its modal chrome, _showModal/IsEditMode/clone-for-edit/SaveModalEntryAsync — per-page edit behaviors Quick Add doesn't need; sharing them would be over-generalization.

3. HouseHistoryForm + HealthRecordForm

    Same pattern: House (DateOnly date, Cost, HouseEventType group, Provider, Description) and Health (HealthEventType group, DateTimeField, appointment-only Specialty/Practitioner/money fields with the live balance preview — MissingAmount and DescriptionPlaceholder move in as pure functions of Entry; the balance rule stays authoritative in HealthMetricsService).
    NewEntry(houseId) / NewEntry(profileId) move in.
    Existing data-testid attributes (e.g. practitioner-input, price-input) travel with the markup — health/car smoke tests depend on them.
    Deliberately not extracted: a generic enum button-group component (the button rows differ in semantics across pages — per-item value vs. filter vs. clear-on-reclick, a conflation CLAUDE.md documents as a past bug).

4. IOwnedCopyDto + OwnedVersionFields

    - New src/WebApi.Contracts/Dto/IOwnedCopyDto.cs: CopyType, Price, AcquiredAt, Vendor, Reference. Implemented by OwnedVersionDto and VideoGamePlatformDto (identical existing members; precedent: IReferenceLinkedDto; no Mapperly impact — mappers map members, not interfaces).
    - New src/BlazorApp/Components/Inventory/Shared/OwnedVersionFields.razor: params required IOwnedCopyDto Copy, optional EventCallback OnChanged (default no-op for Quick Add's nothing-persists-until-Save flow). Body = Physical/Digital button pair + the four fields (invariant-culture decimal parsing included), keeping data-testid="version-*-input".
    - Rewire OwnedVersionsEditor.razor (draft/auto-save/remove/confirm logic and IsEmpty stay) and VideoGameDetail.razor's platform cards (State buttons/playthroughs/fully-completed stay local — only the copy fields move).

5. Quick Add page — picker + media types

    src/BlazorApp/Components/QuickAdd/QuickAddPage.razor + .razor.cs, @page "/add", [Authorize], same render-mode convention as the other interactive pages.

    - [SupplyParameterFromQuery(Name = "type")] string? Type — movie|tv-show|book|album|video-game|car|house|health. Tile clicks navigate va Navigation.GetUriWithQueryParameters (list-page pattern).
    - OnParametersSetAsync: only on an actual Type change, build the fresh draft DTO and clear _error — it also fires on unrelated updates (cascading auth refresh), which must not wipe a half-filled form.
    - Picker: tile grid reusing .kt-stat-grid/.kt-stat-tile with NavMenu's vetted text-presentation glyphs (◼ ▭ ▬ ♪ ◆ ◉ ▲ ✚), data-testid="quickadd-type-*".
    Movie + TV show always visible; the other six tiles AND their forms inside <AuthorizeView Policy="MemberOnly" Context="memberContext"> with the preview-account note in <NotAuthorized> (hiding is UX; the API enforces).
    - Media forms (per-type markup local to the page, same convention as the list FormTemplates):
      - Movie: Title, Year, "Watched on" (FirstSeenAt, default today for the "just saw it" scenario — visible and clearable, since prefilling marks it Seen), Rating.
      - TV show: Title, Year. Book: Title, Author, Year, FirstReadAt default today. Album: Title, Artist, Year (Author/Artist feed Open Library/Discogs auto-resolution).
      - Video game: Title, Year, Platform <select> over VideoGames.VideoGamePlatforms; choosing a platform adds a VideoGamePlatformDto draft rendered via <OwnedVersionFields Copy="..."> — no platform = unowned game.
      - Movie/TvShow/Book/Album: "I own a copy" toggle revealing <OwnedVersionFields>; on save if toggled, dto.OwnedVersions = [_ownedDraft] (a bare Physical copy is legitimate). Single POST carries the copy — no follow-up PUT.
    - Save: SaveMediaAsync<TDto>(InventoryApiClientBase<TDto> api, TDto dto, string route) → AddAsync → navigate {route}/{created.Id}. Errors → _error = ex.Message rendered as .kt-callout danger block (this is where the free-tier quota message shows).

6. Quick Add page — record types

    - Parent fetch on type selection via CarApiClient/HouseApiClient/HealthProfileApiClient.GetAsync("", 1, 100), guarded by a per-type loaded flag.
    - 0 parents → empty-state note linking to /cars / /houses / /health to create one; 1 → preselected silently (the common "my car" case);N → segmented button row.
    - Below it: <CarHistoryForm Entry=... ShowFuel/ShowElectric from the selected car's EnergyType/>, <HouseHistoryForm/>, <HealthRecordForm/>. Selecting a parent stamps the Entry's parent id; Save disabled until a parent is selected.
    - SaveRecordAsync → child client AddAsync → navigate /cars/{carId} / /houses/{houseId} / /health/{profileId}.

7. Entry points + CSS

    - NavMenu.razor: first item inside <AuthorizeView><Authorized> (directly below Home): <NavLink class="nav-link" href="add"><span class="nav-icon">＋</span> Quick add</NavLink>. Verify ＋ (U+FF0B) has default text presentation per the emoji gotcha; plain ASCII + is the safe fallback.
    - Home.razor: stats variant gets a kt-home-cta "＋ Quick add" primary button above the stat grid; the empty-state variant makes Quick Add the primary CTA, "Go to my movies" secondary.
    - CSS: mostly reuse (.kt-stat-grid/.kt-stat-tile, .kt-form-card, row g-3 with col-6/col-12 mobile splits, segmented buttons). New app.css is minimal: a .kt-quickadd block forcing the picker to 2 columns under 767px and a full-width Save button on mobile. Forms live in .kt-form-card on a page, not a modal. No sticky save bar in v1 (forms are short) — note as follow-up.

8. Playwright coverage

    - Pages/QuickAddPage.cs page object + OpenQuickAddAsync() on Pages/PageBase.cs.
    - QuickAddSmokeTest (E2E gate, cleanup via E2eFixture.ApiHttpClient):
      a. Movie with owned copy — GUID-suffixed title, toggle copy + price, Save, assert landing on /movies/{id} with the copy in the Ownership section.
      b. Car refuel — seed a car via API, single car auto-preselected, mileage/fuel/cost, Save, assert landing on /cars/{id} with the refuel row.
    - MobileScreenshotTest: add /add (picker) and /add?type=movie (form) to the 390×844 capture list — the mobile-first acceptance check.
    - Regression safety for the extractions: the existing Car/House/Health/Ownership/VideoGamePlatform smoke tests already cover the refactored surfaces — run them after each extraction step.

## Gotchas to respect

- Razor string-parameter @ prefix (Title="@_x.Title", never bare) when wiring the new components.
- Record DTOs' required members: the moved NewEntry factories are the single construction path — never a bare new().
- Nested AuthorizeView needs an explicit Context= (NavMenu shows the pattern).
- CarDetail.razor.css (scoped CSS) — check whether any scoped rule targeted the moved modal markup; scoped selectors won't reach a chil component without ::deep, so relocate affected rules.

### Verification

- dotnet build; dotnet test (needs local MongoDB + Local.runsettings; Playwright self-skips without E2E_ENABLED).
E2E: E2E_ENABLED=true dotnet test test/BlazorApp.PlaywrightTests/BlazorApp.PlaywrightTests.csproj per the e2e-local-run-recipe memory / CONTRIBUTING.md.
Mobile review: E2E_SCREENSHOTS=true + E2E_SHOTS_DIR screenshot run, plus a manual pass of <https://localhost:5021/add> at 390px width.
Manual regression: the three detail pages' add/edit modals and the game platform cards must behave identically after the extractions (same fields, date/time proxies, balance preview).

## Ready-to-use implementation prompt

To hand this plan to a fresh implementation session, use:

```txt
Implement the "Quick Add" feature described in the plan below.
Read CLAUDE.md first and treat its conventions and quality bar as binding.
Follow the plan's 8 steps in order — the four extraction refactors (steps 1-4) are pure, behavior-preserving refactors and must each build clean (dotnet build) and keep dotnet test green before the next step starts.
Make one commit per step, matching the plan's step titles.
Do not add WebApi/Domain/database changes — the feature is BlazorApp-only plus one contracts interface (IOwnedCopyDto).
Do not extend InventoryPageBase for the new page, and do not introduce a generic enum-button-group component (both explicitly ruled out in the plan).
Where the plan cites approximate line numbers, re-locate the code by its description — the files may have drifted.
After step 8, run the verification section end-to-end and report results honestly, including the mobile screenshot review.

[paste the full plan above]
```
