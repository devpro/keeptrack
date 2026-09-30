# Reference matching findings

How an item is matched to a reference document, and why each rule is as strict as it is.
Video games have their own file, `video-game-matching.md`.

## An alias carries the whole identity of the work, or it is not stored

`matched_aliases` is the local match key: finding an alias links an item with no provider call.
That only works if each alias names exactly one work, so `ReferenceAliasRule` sets what each domain must record:

- **Film, show, game**: title and year.
- **Album**: title and artist, no year, since one release has many pressing years.
- **Book**: title and author, with the year when known, or an ISBN alone.
  The year is recorded but not required: a book with no provider year would otherwise get no alias, and the next "check for reference match" would unlink it.

Refusing an incomplete alias costs one provider call later.
Storing one causes a wrong link that nothing reports.
`scripts/prune-incomplete-matched-aliases.js` removes aliases written under older rules.

Every match path asks the aliases before a provider (`TryLinkKnownReferenceAsync`), creation included.
A stored alias is a settled answer, and a fuzzy provider search can answer differently.

## An automatic link needs a named match, never "the provider returned one row"

Counting results fails both ways:

- **Ordinary titles are refused**: TMDB's fuzzy search returns 8 results for *The Bear* 2022 and 14 for *Heat* 1995, with the right one first.
- **Unrelated titles are linked**: `Fallout` + 2025 returns only *"Thirst Trap: The Fame. The Fantasy. The Fallout."*, and Discogs' `Kid A` + Radiohead + 2001 returns only *Amnesiac*.

`ReferenceMatchRules` confirms a candidate by name plus an identity field, which is required for any automatic link (owner's rule):

- **Film, show, game**: the year, and a single confirmed match links.
- **Book, album**: the creator.
  The year only breaks ties, and several confirmed candidates are printings of one work, so the best one links.
  Candidates must agree with the tenant's creator, not with each other: "J.R.R. Tolkien" and "John Ronald Reuel Tolkien" are one author.

An item without its identity field waits for "check for reference match", which escalates to the provider when nothing local matches.

## Each provider's year filter was measured, not assumed

- **TMDB TV `first_air_date_year` is a hard filter**: `Severance` + 2021 returns nothing, so TV searches with and without the year and merges both.
- **TMDB movie `year` is not**: `Road House` + 2024 still returns the 1989 film, so movies are ranked and searched once.
- **Discogs `year` is a hard filter**, so albums also search with and without it.
- **No book provider sends a year**, each for its own reason.

## An exact spelling beats a loose one

`NormalizeLoose` drops "the" and parenthesised text, which suits comparing two catalogues but not what a tenant typed.
TMDB answers `Alien` 1979 with *Alien* and *The Alien*, so exact matches win and the loose set is used only when there is none.
`Shogun` still links *Shōgun*.

## The title-only lookup refuses to choose

With no year there is nothing to tell "Resident Evil 2" from its seven namesakes.
`FindByTitleAsync` (`ReferenceAliasQueries.FindSingleMatchAsync`) reads two documents and returns a match only when there is exactly one.
Ambiguous and not found mean the same to a caller that must not guess.

The title-only fallback runs only when the tenant has no year.
When a year is known and doesn't match, the item stays unresolved.
Otherwise "Road House" 1989 would link to the 2024 film, and `Resolve*Async`, which reuses the found `Id`, would overwrite one film's reference with the other's.

`FindByTitleYearAsync` is not restricted this way: two documents sharing title and year are a duplicate to merge, not a real ambiguity.

## A record update never changes a reference link

A PUT replaces the whole document, and a detail page opened before background resolution holds a copy with an empty `ReferenceId`.
Its first edit would erase the link, which looked like "it doesn't match, but refresh matches it".
`DataCrudControllerBase.PreserveServerOwnedFieldsAsync` restores the link and its rating fields from storage on every update, the same way `OwnerId` is protected.
Only resolution, the detail page's check and an admin unlink write a link, all through a repository.

## Gotchas

- **Two test classes sharing a title delete each other's references** when they run in parallel, so each class uses its own titles.
- **A duplicate-title defect only shows against real MongoDB**, since it comes from the driver's unsorted `FirstOrDefault`.
