# Reference matching findings

Bugs found in how an item is matched to a reference document: the alias key, the confirmation rules, and the link surviving an edit.
Video game matching has its own file, see `video-game-matching.md`.
Every finding below is fixed.
The rule each one produced is stated in `AGENTS.md`, this file records what went wrong and how it was proven.

## Matched aliases were stored without the field that identifies the work, so the local match key answered questions nobody had confirmed - and the create path never asked it anyway

Found on 2026-08-17, from the owner's report that `matched_aliases` was accumulating entries carrying nothing but a title.

`matched_aliases` is the **local match key**: a lookup that finds an alias links a tenant's item to that reference with no provider call at all.
That only holds while every entry names exactly one work, and three separate paths were writing entries that name many.

- **Every reference repository's `UpsertAsync` added the document's own `(title, year)` pair on every upsert, with no creator.**
  On a book or an album that is a key claiming every author or artist at once - and it was written to every single document in both collections, unreachable by the creator-bearing lookups but sitting in the array forever.
- **A resolve recorded whatever the tenant searched with, year or no year.**
  A title-only alias for a film, show or game matches that title under *any* year - the same defect class as the yearless lookup finding below, one layer earlier: that one stopped a bad *read*, this is the bad *write* that fed it.
- **Album aliases carried a year**, so one release accumulated an entry per pressing year anyone ever typed, none of which narrowed anything: a title plus an artist already identifies the release.

Fixed by declaring what an alias must carry, once per domain, in `Domain/Services/ReferenceAliasRule.cs` - read by the enrichment merge *and* by each repository's canonical-alias safety net, so there is no path left that can write a half-key.
Film/show/game need a title and a year; an album needs a title and a creator and stores no year; a book needs a title and a creator, or an ISBN, and *records* the year whenever one is known (a work is republished as revisions the year tells apart, so the alias names the printing it was confirmed under).
The year is deliberately recorded rather than required there: requiring it would leave a book whose provider reports no year with no alias at all, and an item with no alias is not merely unmatched but actively **unlinked** the next time anyone presses "check for reference match", since finding nothing is what clears a link.
An incomplete combination is refused rather than stored: the cost of refusing is one provider call next time the item is checked, and the cost of storing is a wrong link nothing downstream reports.

**The other half of the finding is that nothing asked the aliases before calling a provider on the path that matters most.**
`TryAutoResolve*Async` - what `<X>Controller.OnCreatedAsync` and every import row run - went straight to the provider, so creating an item someone else already tracks re-derived a fact the database was holding, through a fuzzy search that can answer differently or not at all.
Every one of the five now starts with `TryLinkKnownReferenceAsync`, propagating through the same `Propagate<X>LinkAsync` a fresh resolve ends with.

Books gained the tier that makes this real for that domain: `(title, creator)` regardless of year, asked after the ISBN and the exact `(title, creator, year)`.
A tenant's year routinely names an edition nobody confirmed, and refusing on it sent every reprint to a provider for an answer already stored.
It is also the tier that could guess and does not - `FindByTitleAsync` refuses several matches.

Indexes now follow each domain's lookup instead of one shape for all five (`title`+`creator`+`year` for books, `title`+`creator` for albums, a partial `matched_aliases.isbn`); the old `title`+`year` index matched neither book nor album query's second field, leaving the `ElemMatch` to scan.
Aliases already written under the old rules are pruned by `scripts/prune-incomplete-matched-aliases.js`.

## TV shows, movies, books and albums resolved on "the provider returned exactly one row", which refused ordinary titles and linked unrelated ones

Found on 2026-08-17, by measuring the four remaining providers directly rather than reasoning from the code.
Commit `9b8f5ee` had fixed this class of defect for video games only; the other four domains carried it untouched.
The owner reported it for TV shows and books, and it was equally present, and equally wrong, for movies and albums.

**TMDB's search is a fuzzy match over titles, not an exact one.**
An ordinary title comes back beside every neighbour whose name contains one of its words, with the right answer first and exactly named:

Query | Results | Rank of the right answer
---|---|---
tv `The Bear` 2022 | 8 | 1
tv `Dark` 2017 | 15 | 1
movie `Heat` 1995 | 14 | 1
movie `Alien` 1979 | 9 | 1
movie `Oppenheimer` 2023 | 12 | 1
movie `Sinners` 2024 | 5 | **2**

`candidates.Count != 1` refuses every one of these.
That is the owner's report, and it means **movies failed exactly as visibly as TV shows** - they only looked healthy because a long or unusual title happens to narrow the fuzzy search to a single row.
`Sinners` also shows that a provider's own relevance is not the answer, so the title comparison is what identifies the work.

**The same rule linked things nobody had compared, and that half is silent data loss.**
Two confirmed live:

- `search/tv?query=Fallout&first_air_date_year=2025` returns exactly one result, and it is *"Thirst Trap: The Fame. The Fantasy. The Fallout."* (TMDB 298844).
  The 2024 show is excluded by the year filter, which is what leaves the unrelated one alone in the list.
  This link was really written into the test database by the old rule, and had to be deleted by hand.
- `database/search?type=master&q=Kid A&artist=Radiohead&year=2001` returns exactly one master, and it is *Amnesiac* (Discogs 2507).
  Only the `LooselyContains` title re-check `DiscogsClient` already happened to apply stopped that one being linked.

**The year is a hard filter for two providers and a soft one for a third, and each had to be measured rather than assumed.**

- TMDB TV `first_air_date_year` **is** hard: `Severance` + 2021, `Squid Game` + 2020, `The Wire` + 2003 and `Adolescence` + 2024 each return zero.
  A one-year disagreement means "absent", not "ranked lower", so `SearchTvShowAsync` now asks with and without the year and unions the two.
- TMDB movie `year` is **not** hard: `Road House` + 2024 still returns the 1989 film, `Nosferatu` + 2025 returns the 2024 one first, `Dune` + 2020 returns the 1984 one.
  It narrows without excluding, so movies need ranking only and no second call.
  This contradicted the hypothesis the work started from.
- Discogs `year` **is** hard (the `Kid A` case above).
  This contradicted a comment in `DiscogsClient` stating that no equivalent bug had been found for year; that comment is now corrected.

**Books and albums are identified by a creator, not by a year, and copying the video game rule to them would have been actively wrong.**
`intitle:The Hobbit+inauthor:Tolkien` returns 300 volumes whose first page alone spans 1981, 1999, 2011 and 2012 - all one book, credited variously to "J.R.R. Tolkien", "J. R. R. Tolkien" and "John Ronald Reuel Tolkien".
So for those two domains the year is a tie-break inside the ranking and never a filter, several confirmed candidates are *printings of one work rather than an ambiguity*, and the candidates are deliberately not required to agree with each other about the creator - only with the one the tenant supplied, since demanding they agree reads those three spellings as three authors and refuses the very case the rule exists for.

The fix is `ReferenceMatchRules`, which is `VideoGameMatchRules` hoisted to cover all five domains with two identity shapes, plus `Link<X>ReferenceAsync` escalation on the four remaining controllers so the detail page's button can keep the promise its tooltip makes.
**An identity field is now mandatory for any automatic link in every domain** (owner's rule): a year for films, shows and games, a creator for books and albums.

Deliberately not changed:

- **The book search ladder** (`BookReferenceClientBase`).
  It widens on empty and is multi-provider, so changing what counts as a match changes which rung a query lands on.
  Only what is done with its answers changed.
- **Open Library's `q=` results are still unfiltered**, unlike Discogs'.
  Same reason as before: the book ladder widens on empty, so a filter changes which rung answers.
- **No year was added to any book provider query**, each provider still having its own confirmed reason not to send one.
- **Movies were given no yearless widening**, because TMDB's movie `year` was measured not to exclude.
  Paying a second call per resolve to guard against a failure mode that does not exist would be cargo-culting the TV fix.

One accepted trade, the owner's call and the same one already accepted for video games: requiring a creator means an album or a book recorded without one no longer links on a lucky single hit.
It waits for the detail page's button instead, which now escalates to the provider.

Two things the tests themselves taught, both worth keeping:

- **`NormalizeLoose` drops "the", which is right across catalogues and wrong against tenant-typed text.**
  TMDB answers `Alien` (1979) with both *Alien* and *The Alien*, two different films from the same year that loose matching cannot separate, so the search reported an ambiguity the tenant had already resolved by typing one of the two titles exactly.
  `ConfirmedMatches` now prefers candidates spelled exactly what was asked for and falls back to the loose set only when none are - which still links `Shogun` to TMDB's *Shōgun*.
- **Two test classes sharing a title deleted each other's reference documents.**
  `ReferenceMatchResourceTest` clears a title before exercising it, because the absence of a local reference is its premise; `BookProviderSearchAndLinkResourceTest` links "The Hobbit" through the real providers in parallel.
  Each passed alone and failed together.
  The classes no longer share a title.

## Saving any field on a detail page erased the item's reference link, which is what was really behind "it doesn't match, but if I click refresh it matches"

Found on 2026-08-16, by an e2e assertion the owner insisted on: that editing a title leaves the reference link **unchanged**.
Every earlier attempt had tested what the matching rule returns, and the rule was right every time.

A PUT is a full replace of the document, so every field the client sends wins - and the Blazor detail page sends the whole DTO on every field edit.
Its copy of the item is fetched the instant the page opens, which for a just-created item is *before* the background resolution has linked it.
So the copy carries an empty `ReferenceId`, and the first edit of any field writes that emptiness back over the link the server had already made.

That is the whole reported symptom, and why it looked like a matching bug for so long:

- The match **had** happened - confirmed by an API-level test creating "Resident Evil 2" (2019) and polling, which links within seconds.
- The next edit silently undid it.
- Clicking "check for reference match" resolved it again, so the button appeared to be the thing that worked.
- Nothing about the page changes when a save removes a link, so there was no symptom at the moment of damage.

Fixed once for all five reference-linked types in `DataCrudControllerBase.PreserveServerOwnedFieldsAsync`, over a new `IReferenceLinkedModel` the five models implement: an update restores `ReferenceId` and the three denormalized rating fields from storage, so **a record update can never change a reference link**.
Only resolution, the detail page's check, and an admin unlink write it, and all three go straight through a repository rather than the CRUD controller.
`OwnerId` was already protected this way (overwritten from the caller's claims); this is the same rule generalized to the other field a client was never entitled to set.
One extra read per update, and only for the five types that carry a link.

A second, smaller defect sat on top of it and is fixed too: the detail page never re-read the item after loading, so even with the link intact a just-created game rendered as unmatched until something else caused a fetch.
`Components/Shared/PendingReferenceLink` watches an unlinked item briefly and renders the link when the background resolution lands.

**No test that stops at the API could have found this**, because the API behaves correctly at every individual step - it needs a browser editing a real field on a page holding a real stale copy.

## The yearless title-only reference lookup returned whichever same-titled document the database handed back first, so an item with no year silently adopted an arbitrary work

Found on 2026-08-16, reported from the running app: a video game entered as "Resident Evil 2" with **no year** automatically linked to the 2019 remake's reference - and did it again after the link was deleted as an admin.

This is the half of the "Road House" finding further down that was never closed.
That fix stopped a *known* year from being ignored; the yearless path it deliberately left in place was still a guess.
`I*ReferenceRepository.FindByTitleAsync` was a `FirstOrDefaultAsync` over an unsorted, unbounded `ElemMatch`, so where several reference documents share a title it returned whichever one Mongo happened to yield first - stable enough between runs to look deliberate, which is why it read as "it matched the wrong one" rather than "it guessed".

IGDB holds **eight** games named exactly "Resident Evil 2" (1998 ×3, 1999, 2019, 2024, 2025, one undated) and seven named "Resident Evil".
With no year there is nothing to choose between them with, so nothing may be chosen.

Fixed in `Infrastructure.MongoDb/Repositories/ReferenceAliasQueries.cs`, one shared query over all five reference collections (they differ only in the filter each builds - books and albums additionally narrow by creator), the same shape as `ReferenceStalenessQueries`/`ExploreExclusionQueries`.
It reads **two** documents and returns the match only when there is exactly one.

- **"Ambiguous" and "no match" are the same answer to a caller that must not guess**, so both are null - which is why no call site needed changing: every caller already treats null as "leave it unresolved".
- **A single match still links**, which is the ordinary case and the whole reason a title-only lookup exists.
  Removing the fallback outright would have broken every yearless item that has exactly one candidate.
- Reads two documents rather than counting: "is there more than one" is the entire question.
- Deliberately **not** applied to `FindByTitleYearAsync`.
  Two documents sharing a title *and* a year are a duplicate to be merged (the admin reconciliation screen's job), not an ambiguity to refuse - they are the same work, so either answers, and refusing would break linking until someone merged them.

**Scope, checked rather than assumed:** movies and TV shows carry the identical defect (no creator to narrow with).
Books and albums are structurally far safer - their lookup is `FindByTitleAsync(title, author/artist)`, so a collision needs the same title **and** the same creator - and the many-editions-per-book worry is separately handled, since `MatchedAliases` accumulate and converge a work's editions onto one reference document rather than competing.
All five now go through the shared query anyway.

The other four domains' `TryAutoResolve*Async` keep `candidates.Count != 1` and were deliberately left alone:
TMDB sends the year as a server-side filter so "exactly one result" is genuinely meaningful there, and the book/album search ladders return many editions or pressings so the rule almost never fires at all - conservative in the safe direction.

Covered by `VideoGameReferenceRepositoryTest` (three cases: refuses when several share the title, still matches when only one does, and `FindByTitleYearAsync` picks the requested year out of several) and one `TvShowReferenceRepositoryTest` case proving the shared query is wired into a second domain.
Real MongoDB, necessarily - the defect *is* a driver-level query behaviour and a mocked repository cannot express it.
The tests were written and confirmed failing before the fix.

Existing links already written by the guess are cleaned up by `scripts/unlink-yearless-ambiguous-reference-matches.js` (dry run by default, `APPLY=1` to write, idempotent).
It clears only links that could *only* have been a guess - linked, no year, and the title matching more than one reference - leaving a yearless item with a single unambiguous match alone.
It touches no `*_reference` document, so nothing shared is lost and every affected item stays re-linkable.

## Title-only fallback ignored a tenant-recorded year, so two same-titled but genuinely different items could be silently linked to the same reference document - or, worse, merged into one via `Resolve*Async`

Found on 2026-07-19 (real user report: linking "Road House" (2024) then checking the 1990 original for a match linked it to the 2024 reference instead).
Both `TryLinkExisting{TvShow,Movie,Book,VideoGame,Album}ReferenceAsync` **and** `Resolve{TvShow,Movie,Book,VideoGame,Album}Async` looked up `FindByTitleYearAsync(title, year)` and, on a miss, unconditionally fell back to `FindByTitleAsync(title)` - a title-only lookup that ignores year entirely.
That fallback exists for a real need (a tenant with *no* year recorded at all can never match via the title+year query, since `MatchedAliases` requires both fields on the same element - see the "title-only fallback... must run unconditionally... when Year is null" note further up this codebase's history), but the fix that made it unconditional went too far:
it also fired when the tenant/admin *had* a specific year that simply wasn't yet a confirmed alias, silently ignoring that year and matching whichever same-titled reference document `FindByTitleAsync` happened to return first.
The `TryLinkExisting*` half of the bug was fixed first and initially believed to be the whole story, but the user reproduced the exact same symptom afterward - the real, more serious instance was in `Resolve*Async` (the method the admin's manual "link" action and the automatic single-candidate resolver actually call to create/upsert the reference document).
There, the wrongly-matched document's `Id` is reused for the upsert (`Id = existing?.Id`), so a year-blind title-only match didn't just link the wrong reference - it **overwrote** the unrelated document (e.g. the 2024 remake's reference data got replaced by the 1990 original's), a de-facto merge of two distinct real items into one.
Fixed in both call sites by only taking the title-only fallback when the caller's `year` is `null` - when a specific year is known but doesn't match, the item is left unresolved (or unlinked) rather than guessed at, consistent with this codebase's "don't guess when you don't have the info" principle elsewhere (Watch Next, `TryAutoResolve*Async`).
Covered by `ReferenceEnrichmentServiceTest.TryLinkExisting{TvShow,Movie}ReferenceAsync_DoesNotFallBackToTitleOnlyMatch_WhenTenantHasAYearButTitleYearMatchMisses` and `ResolveMovieAsync_DoesNotMergeIntoAnUnrelatedSameTitledReference_WhenResolvingADifferentTmdbIdWithItsOwnKnownYear`.

Files: `src/WebApi/ReferenceData/ReferenceEnrichmentService.TvShowsAndMovies.cs`, `.Books.cs`, `.Albums.cs`, `.VideoGames.cs`
