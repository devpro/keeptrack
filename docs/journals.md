# Journals

Car, house and health journals: a parent document (a car, a house, a person) with a dated log of entries, stored as a [child collection](data-model.md#child-entities), plus metrics computed from that log.
Their detail pages share `JournalDetailPageBase` (see [Blazor UI](blazor-ui.md#page-bases)).

## Car

`CarHistoryModel.DeltaMileage` is user entered (read off the trip computer), not derived, and `CarMetricsService` cross-checks it against consecutive `Mileage` readings to flag typos or skipped entries.
`CarMetricsService` (consumption across a full refill, cost history, mileage warnings, next maintenance due) is a pure singleton exposed through `CarController.GetMetrics`.

### Stations

**A refuel's station is a reference** (`CarHistoryModel.StationId` to `car_station`), owner-less like the reference collections, since a station at an address is a public fact.
A refuel carries no location of its own, and `CarHistoryController.OnListMappedAsync` hydrates `StationBrandName`/`StationCity` through `CarStationHydrator`, one batched lookup per page.
Maintenance and Other entries keep their own location and free-text `Garage`, having no station to inherit one from.

- **Members create stations inline, admins curate them.**
  `POST /api/car-stations` is find-or-create on the natural key (normalized brand, normalized city, postal code, unique index), so the picker never mints duplicates and a member never waits on an admin.
  `/admin/car-stations` (`AdminOnly`) adds the real city and coordinates and merges duplicates.
- `city_normalized` is `""`, never null or missing, or the unique index would collapse every cityless station onto one key.
- **A station in use cannot be deleted, only merged** (409 naming the count), since deleting blanks every referencing refuel's location.
  The merge re-points every entry (`RepointStationAsync`) before deleting the absorbed document, and fills only the survivor's gaps, adopting the city only when it does not collide with a third station's key.

### Refuel cost check

**The refuel form checks the total against what was pumped, and only warns** (`Common.System/RefuelCostCheck`, shared by `BlazorApp` and `Domain`).
A receipt legitimately differs from the pump (car wash, loyalty discount), so it never auto-fills or blocks, but a missing cost when one is computable counts as a mismatch.
The tolerance derives from what the pump display rounds away (volume to 0.01, unit price to 0.001), since a flat constant false-positives on a big tank and misses a real error on a small one.

`CarHistoryDto.FuelCategory` ("SP95-E10") is offered through `SuggestInput` over `GET /api/car-history/fuel-categories`.

## House

Deliberately smaller than Car, matching the owner's priority: a browsable insurance log plus a yearly cost review, through `HouseMetricsService.ComputeAnnualCostHistory` only.
`HistoryDate` is a `DateOnly`, and one `Provider` field covers every category.

## Health

The parent is a person (`HealthProfileModel.Name`), and both controllers are `MemberOnly`.
`HistoryDate` is a full `DateTime` like Car's, since appointment time is real data, stamped UTC through an explicit `[MapProperty(Use = ...)]` in `HealthRecordStorageMapper`.

The money model is the French reimbursement flow: `Price`, `PublicReimbursement`, `InsuranceReimbursement`, `NotCovered`.

- A record is settled when `price - public - insurance - notCovered == 0` within `HealthMetricsService.BalanceTolerance` (0.005).
  Anything else lands in `HealthMetricsModel.UnbalancedRecords` with the signed missing amount.
- **The balance rule lives only in `HealthMetricsService`**: the journal's "to check" badges come from the metrics' id list and are never re-derived client side.
  The form's live balance preview is display only.
- The detail page is journal-first and badge-only (owner's call): no "to check" list, no chart, no per-row reimbursement column, the yearly table after the journal.
- **`Specialty` and `Practitioner` are free text with suggestions over what this account already recorded** (`GET /api/health-records/suggestions`, both lists in one `HealthRecordSuggestionsDto` since the form needs both at once).
  They are owner scoped and never a shared catalogue: a doctor's name is one account's medical history, not a public fact.

## Charts

Charts are Razor components drawing SVG markup (`ConsumptionChart`, `CarCostHistoryChart`, `HouseCostHistoryChart`), never `RenderTreeBuilder` code with computed sequence numbers (`ASP0006`).
Axes are drawn once by `Components/Shared/ChartAxes.razor`, geometry and coordinate formatting live in `SvgChartHelpers`, and each chart keeps its own series drawing.

**SVG coordinates are always formatted with the invariant culture** (`SvgChartHelpers.ToSvg`), since a host under a decimal-comma culture would write `40,0` and break every chart.
Chart CSS (`.kt-callout*`, `.kt-chart-*`, `.kt-sheet-table`, `.kt-legend-*`) is global in `app.css`.
House's yearly cost chart is a single-series bar chart plus a breakdown table.
