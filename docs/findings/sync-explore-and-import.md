# Sync, Explore and import findings

Why the scheduled and background work is shaped as it is: reference sync, the Explore catalogue, the rating recompute and reference-data import.

## Explore's exclusion depends on every reference carrying the default provider's id

Explore excludes a tracked game by the discovery provider's id, then by title.
Both fail on a reference linked under a previous provider:

- **By id**: a RAWG-linked reference has no `igdb` id until `TryAdoptDefaultVideoGameProviderAsync` adopts one.
- **By title**: providers spell one work differently (`Mass Effect: Legendary Edition` vs `Mass Effect Legendary Edition`, RAWG's `GoldenEye 007 (1997)`), so the title half uses `NormalizeLoose`.

The fix is adoption, not a workaround in Explore:

- `FindAdoptionCandidatesAsync` widens its query ladder only when nothing matched, and `ProviderAdoptionCheckedAt` retries a failure after 7 days.
- `TitleNormalizer.NormalizeLoose`/`LooselyEqual`/`StripDisambiguator` serve provider-to-provider matching, while `Normalize` stays strict since it keys aliases against tenant text.
- What adoption refuses to guess goes to the admin provider reconciliation screen, whose merge re-points every tenant item (`RepointReferenceAsync`) before deleting.

Explore dismissals keep the provider they were recorded under, so switching back to a previous provider restores them (owner's call).

## Selectable rating sources come from the default provider

`RatingSourceOptions` derives a domain's sources from the default client's `SupportedRatingSources`.
A hardcoded list kept `metacritic` selectable under IGDB, which reports none.
An override not on offer is ignored, never erased, so switching provider back restores it.

## Reference-data import matches by provider id, never by exported `_id`

An `_id` is only meaningful in the source database: elsewhere the same TMDB id lives under another `_id`, and the unique `movie_reference_tmdb_id` index rejects the insert.

- **The target's `_id` is kept**, since every tenant's `ReferenceId` points at it.
- **People are imported first** and every `PersonReferenceId`/`AuthorReferenceId`/`ArtistReferenceId` re-pointed, since a missing person renders as no cast, silently.
- **A match merges, never replaces**: the target's `MatchedAliases` and `Ratings` (including metered OMDb values) exist nowhere else.
- **`external_ids` uniqueness needs one index per provider that can write a collection**, or duplicates from a second provider pass unchecked.
- **Possible duplicates are reported, never merged**, since title text is not identity.

`ReferenceDataImportResourceTest` runs against real MongoDB, since the failure is the unique index firing.

## Reference-data import is a background job

A real export is about 17 000 documents written one at a time, which takes minutes and outlives `HttpClient`'s 100s timeout while the server keeps importing.
It runs on `JobStore<TStage, TResult>` (202 plus job id, polled), on `ApplicationStopping`, and is idempotent so a re-run picks up what didn't land.
The upload is buffered before the POST, since streaming it from the Blazor circuit counts against the timeout.

Known limit: one round trip per document; `BulkWrite` batching would cut minutes to seconds but touches all six repositories.

## Gotchas

- **A request timeout leaves no trace in the WebApi logs**, since `"Microsoft": "Warning"` hides request start and finish.
- **`$lte` against a date matches neither null nor missing**, so `FindStaleAsync` checks "never enriched" separately rather than through the date comparison.
- **The rating recompute stays cheap only through `ReferenceRatingSource`**: without the stored source it can't tell a correct item from a stale one and rewrites everything.
