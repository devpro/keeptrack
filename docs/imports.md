# Imports

Bulk imports of a user's own data: store and retailer transaction exports, and the TV Time export.
The reference-data export and import, an admin tool, is in [Reference data](reference-data.md#export-and-import).

## Store and retailer transactions

Three importers of the same shape, the controller in `Controllers/` and the pure parsing and computation in `Domain/Services/`.
Each is a preview then a commit: the user reviews and selects rows before anything is written.

Importer | Controller and service | Input
---------|------------------------|------
Generic | `GenericImportController`, `GenericImportService` (`POST /api/import/generic`, `MemberOnly`) | Any CSV with the canonical columns
Amazon | `AmazonImportController`, `AmazonOrderPreviewService` | Amazon's order-history CSV
Video game | `GenericVideoGameImportController`, `GenericVideoGameImportService` | A video-game-only transaction CSV, such as PSN's GDPR export

**The generic importer is the store-agnostic default, extended rather than adding another store-specific importer.**

- It reads a canonical, case-insensitive column set, all optional except `Title`.
- A `Type` column sets each row's `ImportMediaType` (`ParseMediaType` tolerates "TV Show", "Video Game", "Film", "Jeu"), and a blank or unrecognized value falls back to the per-row picker rather than guessing.
- Aliases cover real headers: `Product Name` to Title, `ASIN`/`SKU` to `ProductId`, `Total Amount` to Price, `Product Condition` to Condition.
- `Vendor` becomes the copy's Vendor and `Website` its `Reference`, and `Condition` is kept on the copy's `ProductName` (owner's request).

The Amazon importer keeps only what is Amazon-specific: `AmazonImportMergeService.FormatOrderReference` (ASIN plus order id) and `BuildAmazonProvenanceNotes`.
The video game importer takes `Vendor` as a per-row column, so any store with that shape works.

**Two personal spreadsheet importers live beside the TV Time one in `src/WebApi/Import`.**

- `CarHistoryImportController` and `CarHistoryImportService` import `Voitures.xlsx`, the fuel and maintenance history per car.
- `HealthImportController` and `HealthImportService` import `Journal_sante.xlsx`, one sheet of health events with every family member in a `Personne` column.
- Both share `ExcelCellParser`, and the house journal has no importer.

### Shared engine

The merge is written once: `Domain/Services/OwnedItemImportMergeService.cs` (`ComputeCommitPlan`, `FindImportedReferences`) matches by normalized title through `TitleNormalizer`, merges within the same commit batch,
and returns `Domain/Models/ImportCommitPlan.cs`.
`Domain/Services/OwnedItemImportCommitCoordinator.cs` owns the per-type create and merge orchestration for both multi-type controllers.
The engine takes one `OwnedItemImportAdapter<TModel, TRequestItem>` rather than six separate delegates (Sonar `S107`).

- **An import reference or dedup key needs a per-product disambiguator**: the product name for PSN, the ASIN for Amazon, the order id plus product id for generic.
  One PSN transaction bundles several products (three "Far Cry 4" DLC packs), so transaction plus order id collides and silently skips lines as duplicates.
- **`VideoGamesCreated`/`VideoGamesMergedInto` count distinct items, not rows**, since rows sharing a normalized title consolidate into one item.
  `RowsImported` is the per-row count (`RowsImported + Skipped` equals the rows submitted), and `SkippedRowTitles` names the rest, so the UI shows "X of Y selected rows imported".

## TV Time

`POST /api/import/tv-time` takes TV Time's export zip and runs as a [background job](architecture.md#background-work).
Everything below was confirmed against real export data.

- `seen_episode_source.csv` alone is incomplete, so `tracking-prod-records.csv` and `-v2.csv` are merged and deduplicated per (show, season, episode), the earliest date winning.
- `followed_tv_show.csv` is incomplete too, so `ImportEpisodesAsync` creates shows from watch events and never skips an unfollowed show.
- Movies carry watch dates in `tracking-prod-records.csv` (`entity_type == "movie"`: watch, towatch when unwatched, follow), and `-v2.csv` has no movie data.

### Idempotency

**A re-import is safe, matched by stable id, never by title**, since reference resolution rewrites `Title`.

- Imported items carry `TvTimeId` (`IHasTvTimeId`, round-tripped on edits): TV Time's show id or the movie's tracking `uuid`, else a deterministic `tvtime_title:<normalized export title>` through `ResolveTvTimeId`.
  `BuildIdByTitle` maps the title-only files onto the id-bearing ones.
- `UpsertIndex<TModel>` matches by `TvTimeId`, falls back to the title only for a record with no id yet (back-filled once by `BackfillTvTimeIdAsync`), and leaves a record with a different id alone.
- **A matched record is never modified**, so edits made in the app survive a re-import.

**Gotcha:** a CSV property missing from some files' headers needs CsvHelper's `[Optional]` on top of being nullable, or header validation throws.
