# Collections

The tracked items themselves: media, gear, collectibles and playlists, plus the features built on top of them (Wishlist, Watch Next, Quick Add, user preferences).
Journals (car, house, health) are in [Journals](journals.md), and how media links to provider data is in [Reference data](reference-data.md).

## Media

Movies, TV shows, books, albums and video games are reference-linked: each item can point at a shared reference document holding provider metadata (cover, synopsis, cast, ratings).
TV show episodes are a [child collection](data-model.md#child-entities).

## Ownership

An item is owned exactly when it has at least one owned copy, so there is no stored `is_owned` flag to drift.

- Movies, TV shows, books, albums, gear and collectibles embed `List<OwnedVersionModel>` (`owned_versions`): `CopyType` (`Physical` first so it is the default, or `Digital`),
  an optional `Price` (`decimal` stored as Decimal128, currency agnostic), `AcquiredAt` (`DateOnly`), `Vendor`, and a free-text `Reference` (edition or order number, unrelated to `ReferenceId`).
- **Video games have no `OwnedVersions`**: their per-platform entries carry a `CopyType` and are the copies, so a game is owned when `Platforms` is non-empty.
  `VideoGamePlatformModel.ProductName` (the store's own product or edition text) renders through `OwnedVersionFields`' `ExtraFields` slot rather than joining `IOwnedCopyDto`, since no other type has the concept.
- `IsOwned` exists only as a query parameter: repositories translate it to `SizeGt(OwnedVersions/Platforms, 0)`, the `*_owned` partial indexes match that predicate, and storage mappers ignore it both ways.
- Detail pages share `OwnedVersionsEditor`/`OwnedVersionFields` (`Components/Inventory/Shared/`, unnumbered `col-md` columns so an extra column re-shares the width), and list rows derive the Owned badge from `OwnedVersions.Count > 0`.
- A new copy is a draft card with Save and Cancel, an already-saved copy auto-saves on change like every other detail field, and removing a saved non-empty copy asks through `ConfirmModal`.

## Gear and collectibles

Ordinary owned collections with no reference document: title, brand, year, notes, favorite flag, owned versions, and a tenant-owned `ImageUrl`.
Gear adds a free-text `Category`, one per item, suggested through `SuggestInput` over the categories this account already used (`FindDistinctValuesAsync`).
With no shared reference identity, they can be shared as a list but never copied (see [Sharing](sharing.md)).

## Playlists and songs

A playlist holds `SongIds` in playback order: the list's own order is the playlist order, with no position field.
A song optionally points at the tenant's own album (`AlbumId`), a soft reference with no cascade delete.

A song is usually created by picking a track from the linked album's reference tracklist, which fills `Duration` and `TrackPosition`.
`AlbumId` plus `TrackPosition` is a track-based song's identity, so picking the same track twice reuses the song (`SongApiClient.GetOrCreateForTrackAsync`, over `SongRepository.GetFilter`'s exact match).

## Wishlist

An item is on the wishlist through its own `IsWishlisted` flag (movies, TV shows, books, video games), and `WishlistController` aggregates the flagged items across types.
The wishlist can be shared through an anonymous link (see [Sharing](sharing.md#wishlist-link)).

## Watch Next

`WatchNextService.ComputeInProgressShows(shows, episodes, referencesByShowId)` reports a show only when its `State` is `TvShowStatus.Current` **and** the reference's episode list has an entry after the last one watched,
compared by `(SeasonNumber, EpisodeNumber)`, whose `AirDate` is past or unset.
A show with no reference is excluded rather than guessed at, and `InProgressShowDto.Next*` reports that confirmed next episode.

`FilterMoviesToWatch` excludes a movie once `FirstSeenAt` is set even if `WantToWatch` is still true, since the flag can go stale.
**`WantToWatch` is movie only**: a "shows to start" surface would be a real Watch Next section, not a flag.

`TvShowDetail.razor`'s episode checklist hides episodes not yet aired.
Once the show has a `ReferenceId` it is a full watch-through checklist (checking creates an `Episode`, unchecking deletes it), and without one it falls back to recorded episodes plus a manual add form.

## Quick Add

`/add` captures any entry from one mobile-first form: the eight types are movie, TV show, book, album, video game, and a car, house or health record.
The selected type lives in the URL (`/add?type=movie`), so the back button returns from the form to the picker and deep links work.

- It is BlazorApp only, going through the existing API clients, so creation enforces the free-tier quota and fires reference resolution exactly as a list page's Add does.
- It does not extend `InventoryPageBase`, so the record DTOs' `required` members cause no `new()` constraint problem.
- The record forms (`CarHistoryForm`, `HouseHistoryForm`, `HealthRecordForm`) and the copy fields (`OwnedVersionFields`) are the same components the detail pages use, and each form's `NewEntry` factory is the single way to build a new record.
- A media item can carry one owned copy in the same POST, and a video game's platform entry is its copy.
- A record needs its parent: none links to the page creating one, a single one is preselected, several show a choice.
- After saving, it lands on the created item's detail page, or the parent's detail page for a record.
- `OnParametersSetAsync` rebuilds the draft only when the type actually changes, since it also fires on unrelated updates (a cascading auth refresh) that must not wipe a half-filled form.
- Enum button rows stay per page rather than one generic component, since their semantics differ (per-item value, filter, clear on re-click).

## User preferences

One document per user, with the toggles under `Features` (`UserPreferencesFeaturesModel`), each a named boolean rather than a generic settings dictionary.
They are optional links: `ShowChasseAuxLivresLink` next to a book's ISBN, and `ShowAmazonProductLink` next to an owned copy whose `Reference` holds an ASIN from the Amazon import.
