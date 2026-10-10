# Reference matching

How an item is matched to a reference document, and why each rule is as strict as it is.
Resolution, the check button and what a link reaches are in [Reference data](reference-data.md#enrichment).

The principle behind every rule: **leave an item unlinked rather than link it wrongly**.
A refused match costs a provider call or an admin action later, and a wrong one is a silent error nobody reports.
A lower unattended-link rate is the design, not a regression (owner's call): when matching looks too strict, the query is improved, never the definition of identity.

## Local aliases

`MatchedAliases` (`List<ReferenceMatchModel>`: `Title`, `Year`, `Creator`, `Isbn`) records every combination confirmed to mean this work, merged and never overwritten.
Finding an alias links an item with no provider call.

**Every match path asks the local aliases before a provider** (`TryLinkKnownReferenceAsync`, first in every `TryAutoResolve<X>Async`, and the whole of `TryLinkExisting<X>ReferenceAsync`).
A stored alias is a settled answer, and re-deriving it through a fuzzy provider search is at best slower and at worst different.

Queries use `Builders.Filter.ElemMatch` so every condition holds on the same element, written once in `Infrastructure.MongoDb/Repositories/ReferenceAliasQueries.cs` over `IHasMatchedAliases`.
Indexes follow each domain's lookup (`title`+`year`, `title`+`creator`+`year`, `title`+`creator`, partial `matched_aliases.isbn`), or the `ElemMatch` scans the collection.

### An alias carries its domain's whole identity, or is not stored

`Domain/Services/ReferenceAliasRule.cs` sets what each domain records, since a half key answers questions nobody confirmed.

- **Film, show, game: title plus year** (`TitleAndYear`).
- **Album: title plus creator, no year** (`TitleAndCreator`), since one release exists as many pressings under many years.
- **Book: title plus creator, with the year when known** (`TitleAndCreatorWithYear`), or an ISBN alone.
  The year is recorded but not required: a book with no provider year would otherwise get no alias, and the next "check for reference match" would unlink it.
- `Creator` always comes from the canonical provider response, never from tenant text, and `Isbn` is recorded only on the alias that used it.

The book lookup is a ladder (`FindKnownBookReferenceAsync`): ISBN, then `(title, creator, year)`, then `(title, creator)` whatever the year.

`scripts/prune-incomplete-matched-aliases.js` removes aliases that do not meet these rules.

### The title-only lookup refuses to choose

`FindByTitleAsync` returns a match only when there is exactly one (`ReferenceAliasQueries.FindSingleMatchAsync` reads two documents), since ambiguous and not found mean the same to a caller that must not guess.

The title-only fallback runs only when the tenant has no year, and it runs even then, since `FindByTitleYearAsync(title, null)` only matches a reference whose year is also null.
When a year is known and does not match, the item stays unresolved: "Road House" 1989 would otherwise link to the 2024 film, and `Resolve*Async`, which reuses the found `Id`, would overwrite one film's reference with the other's.

`FindByTitleYearAsync` and the album lookup are not restricted this way: two documents sharing the whole identity are a duplicate to merge, not a real ambiguity.
Video games have no title-only fallback at all (see [Video games](#video-games)).

## Confirming a provider match

**Automatic resolution confirms a named match, never that a provider returned one row** (`ReferenceMatchRules`, shared by all five domains).
Counting results fails both ways:

- **It refuses ordinary titles**: TMDB's fuzzy search returns 8 results for *The Bear* 2022 and 14 for *Heat* 1995, with the right one first.
- **It links titles nobody compared**: `Fallout` + 2025 returns only *Thirst Trap: The Fame.
  The Fantasy.
  The Fallout.*, Discogs' `Kid A` + Radiohead + 2001 returns only *Amnesiac*, and IGDB answers `NieR:Automata` with only *Untitled NieR:Automata Project*.

There are two identity shapes, a real difference between domains:

- **Film, show, game: title plus year** (`ConfirmedMatches`), and a single confirmed match links.
- **Book, album: title plus creator** (`ConfirmedCreatorMatches`).
  The year only breaks ties, and several confirmed candidates are printings of one work, so the best one links.
  Candidates must agree with the creator the tenant supplied, not with each other: "J.R.R. Tolkien" and "John Ronald Reuel Tolkien" are one author.

**An identity field is required for any automatic link** (owner's rule): a year for films, shows and games, a creator for books and albums.
Without it, the item waits for "check for reference match".

### An exact spelling beats a loose one

`NormalizeLoose` drops "the" and parenthesised groups, which suits comparing two catalogues but not what a tenant typed.
TMDB answers `Alien` 1979 with *Alien* and *The Alien*, so the loose tier is used only when nothing matches exactly, and `Shogun` still links *Shōgun*.

`TitleNormalizer.Normalize` stays strict, since it keys stored aliases against tenant text.
`NormalizeLoose`, `LooselyEqual` and `StripDisambiguator` serve provider-to-provider matching.

### Each provider's year filter was measured

**A hard year filter is never the only query asked.**

- **TMDB TV's `first_air_date_year` is a hard filter**: `Severance` + 2021 returns nothing, so TV searches with and without the year and unions the results.
- **TMDB movie's `year` is not**: `Road House` + 2024 still returns the 1989 film, so movies are ranked and searched once.
- **Discogs' `year` is a hard filter**, so albums also search with and without it.
- **No book or video game provider sends the year as a filter**, so a wrong year costs a place in the list, never the result.

### Ranking

`ReferenceMatchRules` is the single declaration of "is this candidate that work", read by search ranking, automatic resolution and provider adoption.

- `OrderByBestMatch` ranks by names-the-work (`TitleNormalizer.LooselyEqual`), then year, then title distance (an edition or DLC is the game plus something), then title, **never by provider relevance**.
- `YearRank` is three-state: the requested year, then no year reported, then a contradicting year.
  Treating "unknown" as a contradiction discards a dateless right answer, and treating it as agreement floats a dateless namesake above the real match.
- `ConfirmedMatches` keeps only the best year tier any candidate reaches, so an undated namesake never blocks the matching-year one, and a contradicting year never confirms however alone the candidate is.

## Search policies

Books and video games are the multi-provider domains, and each has its search policy written once in a base class, a provider supplying only its primitive queries.

**Books** (`BookReferenceClientBase`): ISBN alone, then title plus author, then title alone, widening only on an empty step, an ISBN miss included (BnF may not know an ISBN that Open Library finds by title).
A provider supplies `SearchByIsbnAsync`/`SearchByTitleAsync`.

**Video games** (`VideoGameReferenceClientBase`): `FindGamesByExactTitleAsync` first, unioned with a `RelevancePoolSize` (50) relevance pool, then ranked as above.
A provider's own ranking truncated to five loses the game: IGDB ranks the 2019 *Code Vein* sixth, behind its sequel and DLC.

## Video games

The hardest domain: catalogues are full of same-titled works, remakes, editions and DLC.
Every regression here is worth a test.

- **`TryAutoResolveVideoGameAsync` links a single confirmed match and requires a year**, and this domain has **no** title-only local fallback (owner's rule).
  IGDB holds eight games named exactly "Resident Evil 2", three of them from 1998.
- A title the provider spells differently goes to the admin queue rather than linking automatically (owner's call).

### Adopting the default provider's id

IGDB (`igdb`) is the default and RAWG (`rawg`) stays registered for admin search, and so that its stored values keep rendering.
**A reference linked before the default changed adopts the new provider's id during the sync** (`TryAdoptDefaultVideoGameProviderAsync`), with no migration script.
It requires exactly one candidate whose title matches the reference's with a compatible year, since the reference's own title is canonical data.

- **A failed adoption breaks Explore**: its exclusion asks each linked reference for the discovery provider's id, so an unadopted reference is a tracked game that keeps being suggested (see
  [Explore](explore.md#excluding-what-the-user-tracks)).
- `FindAdoptionCandidatesAsync` runs a ladder, widening when nothing **matched** (not when nothing came back, since a relevance search answers with unrelated results), and accumulating candidates across rungs:
  1. the exact title (`where name ~ "..."`);
  2. the same with `TitleNormalizer.StripDisambiguator` (RAWG's `GoldenEye 007 (1997)`);
  3. `TitleNormalizer.ToProviderQuery` (`NieR Automata` finds what `NieR:Automata` does not);
  4. trailing words dropped (`MaxTruncatedQueries` = 3, never below `MinTruncatedQueryWords` = 2);
  5. every word as a substring (`FindGamesContainingAllWordsAsync`), shortlisted to the eight closest titles.
- Confirmation is always against the reference's title with `NormalizeLoose`, never against the query that found the candidate.
- `Marvel's Avengers` is deliberately not adopted unattended: a rule equating it with `Marvel Avengers` would equate `The Sim` with `The Sims`.
- A fruitless attempt is stamped (`ProviderAdoptionCheckedAt` per provider, retried after `ProviderAdoptionReattemptAfter` = 7 days), and the admin action ignores the window.
- A reference that cannot be adopted keeps its data and is stamped as checked, so the staleness queue rotates past it.

### Provider reconciliation

`GET/POST /api/reference-data/provider-reconciliation*` (`AdminOnly`, video games only) resolves what adoption refuses to guess, plus the duplicates a provider change leaves behind.

- The gap list and duplicate groups are database reads (`FindWithoutExternalIdAsync`, `Exists(..., false)`), and candidates are fetched per row on demand.
- A row is searched with admin text, or a pasted provider URL or numeric id (`FindGameByIdentifierAsync`).
  `ProviderWebLinks.TryReadIdentifier` treats nothing else as an address, since `Half-Life` looks like a slug.
- `AdoptVideoGameProviderIdAsync` writes the id onto the existing document, then reuses `RefreshVideoGameReferenceAsync`, never `ResolveVideoGameAsync`, which could mint a second document.
  It refuses when another document claims the id, naming it.
- `MergeVideoGameReferencesAsync` fills the survivor's gaps, re-points every tenant item (`RepointReferenceAsync`), then deletes the absorbed document.
  `MergedImageUrl` is computed before the ids are unioned, since "is this a RAWG image" is "does this document carry a rawg id".

## Gotchas

- **A title typed without its punctuation misses the exact-name query**: "code vein season pass" is found only through the relevance pool plus loose confirmation, which a unit test feeding `ConfirmedMatches` directly cannot see.
- **A leftover reference makes an escalation test pass falsely**, since the local lookup answers instead of the provider.
  `VideoGameReferenceMatchSmokeTest` deletes every reference it causes (`End2EndFixture.RemoveVideoGameReferencesAsync`), and `RefreshReferenceResourceTest` asserts its premise up front.
- **Two test classes sharing a title delete each other's references** when they run in parallel, so each class uses its own titles.
- **A duplicate-title defect only shows against real MongoDB**, since it comes from the driver's unsorted `FirstOrDefault`.
