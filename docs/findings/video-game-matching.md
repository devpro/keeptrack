# Video game matching findings

Video games are the hardest matching domain here, and the only one whose regressions kept reaching the owner, so its findings are kept apart from the other four.
Every finding below is fixed.
Read these before loosening anything about how a game is matched to its reference.

## Video game matching was tested only as a rule, never as a journey, so three regressions in a row reached the owner instead of a test

Found on 2026-08-16, after the owner reported the same feature broken three times while every unit test stayed green.

The matching rule had thorough coverage.
The path a person walks had none, and that is where every failure was:

- **A title typed without its punctuation never reaches the provider's exact-name query.**
  "code vein season pass" is IGDB's "Code Vein: Season Pass"; `where name ~ "..."` returns nothing for it and only the relevance rung plus loose confirmation finds it.
  A test that hands candidates to `ConfirmedMatches` directly cannot see this.
- **An item created before its year is known writes no reference at all**, so the detail page's local-only "check for reference match" had nothing to find however correct the title and year later became - while its own tooltip promises *"Not right? Edit the title or year below, then check again."*
- **Editing a title has to both re-point and clear a link**, and neither was covered anywhere.

Two behaviour changes came out of it, both video-game-only:

- **A year is required for any automatic link** (owner's rule).
  `TryAutoResolveVideoGameAsync` returns immediately without a year and the domain's title-only local fallback is gone, so a title alone can never link - not even where the provider happens to hold exactly one game by that name.
  Video game catalogues are full of same-titled works; the cases where a bare title identifies one game are not worth a rule that silently links the wrong thing everywhere else.
- **"Check for reference match" escalates to the provider when nothing local matches** (`LinkVideoGameReferenceAsync`), which is what makes the year not a one-shot chance taken at creation.
  It adds no new guessing - it links exactly what resolution on create would have linked.
  Deliberately not applied to the other four domains, whose auto-resolve still fires on "the provider returned exactly one result"; escalating on that would turn a local-only control into a provider call that can link something nobody compared.

**Updating a field never searches by itself** - the user clicks the button, and that is the only thing that re-resolves.
There is no update hook, on purpose.

Covered by `VideoGameReferenceMatchSmokeTest`, three Playwright scenarios through the real UI, real circuit, real API, real MongoDB and real IGDB: edit a linked game's title to another real game and it re-points; edit it to something no game is called and the link is cleared; create without a year, get nothing, add the year and check, and it links.

**These tests were verified by mutation, and the first version of them was worthless.**
Disabling the provider escalation left all three green, because the reference documents an earlier run had left behind let the *local* lookup answer instead - a false green of exactly the kind this whole finding is about.
They now remove every reference they cause to be created (`End2EndFixture.RemoveVideoGameReferencesAsync`), and with the escalation disabled two of the three fail.
The third legitimately does not depend on it.
Same trap and same fix in `RefreshReferenceResourceTest`, whose video game cases assert the premise up front rather than passing quietly when a leftover satisfies them.

The five detail pages' refresh button gained `aria-label="Check for reference match"`; it was an icon-only button with no accessible name, and once an item is linked an admin also sees the unlink button carrying the same `.kt-icon-btn` class, so the old class-based locator matched two elements.

## Video game search dropped the year on the floor and truncated the provider's ranking to five, so a title matching name *and* year exactly was routinely not among the results

Found on 2026-08-16, reported from the running app: searching "Code Vein" with year 2019 returned five candidates, none of which was the 2019 game of that name.

Two independent defects, both in the search path an admin and `TryAutoResolveVideoGameAsync` use:

- **The year was never used at all for IGDB.**
  `IgdbClient.SearchGamesAsync` took an `int? year` and ignored it - deliberately not sent as a filter (correctly: a hard year filter is the zeroing-out trap `OpenLibraryClient` and `DiscogsClient` document), but it was never used as a tie-break either, which the comment claimed the caller would do and no caller did.
  `RawgClient` had the opposite defect: it sent the year as a hard `&dates=` filter, so a game whose RAWG release date falls in the year either side of the one a tenant typed was not ranked lower, it was absent.
- **The provider's ranking was truncated before anything looked at it.**
  Both clients asked for only 5 results and returned them verbatim, so relevance alone decided what an admin ever saw.
  Confirmed live against IGDB: `search "Code Vein"` ranks the 2019 game **sixth**, behind its own sequel, three DLC packs and a season pass.
  `search "Resident Evil"` is worse - the first six hits are bundles and archive re-releases, and the seven games actually named "Resident Evil" begin at rank 7.
  This is the same 5-result-window failure already recorded above for adoption (`FindGamesByExactTitleAsync` was added to fix it there), and the interactive search path simply never got the same treatment.

Not cosmetic, and the same two-sided cost as the Discogs finding above: `TryAutoResolveVideoGameAsync` acts only on a single candidate so it could never fire, and the admin picker shows `MaxEnrichedCandidates` (5), so the game was unlinkable by hand as well.

Fixed by writing the policy once in `WebApi/ReferenceData/VideoGameReferenceClientBase.cs`, the same shape as `BookReferenceClientBase`: each client now supplies only `SearchByRelevanceAsync(title, limit)` (no year - see below), and the base asks `FindGamesByExactTitleAsync` first, unions the relevance pool, and ranks.

- **A game the provider holds under exactly this name is fetched directly rather than hoped for from relevance**, which is what makes "a perfect title match always appears" a guarantee rather than a probability - relevance can bury it arbitrarily deep, or (confirmed for "Marvel's Avengers") never return it at all.
- **The relevance query reads 50 and the ranking picks the 5 that are shown.**
  Truncating first and ranking second is exactly how the right candidate got lost; the whole "Resident Evil" ranking is only 48 entries deep, so the extra depth is one page either way.
- **One declaration of "is this candidate that game"**, `VideoGameMatchRules`, read by the search ranking, by automatic resolution and by provider adoption alike - they were three separate opinions about one question, of which only adoption's had been thought through.
  `OrderByBestMatch` orders every candidate list a human sees: names the work, then the year, then title distance (an edition/DLC/bundle is the game plus something, so the shortest is closest to what was asked for), then title for a total order.
  The provider's own relevance is deliberately not a key - it is what buried the answer at rank six.
  This is the ordering the admin reconciliation row already used; the search path and the substring shortlist now share it rather than each having their own.
- **The year is three-state, not a boolean**: the requested year, then a candidate the provider reports *no* year for, then a contradicting year.
  Both folds are wrong and were measured: fold "unknown" into "contradicts" and a provider with no date for a game discards the right answer; fold it into "agrees" and it counts as confirmation, which floated IGDB's dateless "Resident Evil" (102722) above the 2002 remake.
- The year is still never sent as a server-side filter, though a live probe confirmed Apicalypse accepts `where first_release_date` alongside `search`.
  Being wrong about a year now costs a place in the list instead of the whole result, which is the same rule the book and album clients' retries exist for.
  RAWG's `&dates=` filter was removed for that reason.

## Automatic video game resolution decided on how many results the search returned rather than on whether any of them was the game

Found on 2026-08-16 while fixing the search above, and the same root cause: the year was available and nothing used it to decide anything.

`TryAutoResolveVideoGameAsync` linked when `candidates.Count == 1`, which reads a property of the *search* as a property of the *answer*.
Wrong in both directions:

- **It linked candidates it never compared.**
  IGDB answers "NieR:Automata" with a single "Untitled NieR:Automata Project" and would have linked it - a wrong link, silently, on an ordinary create.
- **It refused every title with namesakes, however unambiguous the year made it.**
  IGDB holds **eight** games named exactly "Resident Evil 2" (1998 ×3, 1999, 2019, 2024, 2025, and one undated) and seven named "Resident Evil".
  For those the title is no evidence at all about which is meant and the year is the only thing that is - yet a tenant recording the 2019 remake could never resolve automatically, though only one of the eight is from 2019.

Widening the search pool would have made this strictly worse on its own: with a 50-deep pool and an exact-name query unioned in, `Count == 1` almost never holds, so auto-resolution would have quietly stopped firing at all.

Now it links on a single `VideoGameMatchRules.ConfirmedMatches` - a candidate actually named this game, agreeing about the year.
`ConfirmedMatches` returns only the best year tier any candidate reaches, which is what makes the year decisive: a search for "Resident Evil 2" (2019) finds the 2019 game *and* the undated namesake, and reporting that as an ambiguity would strand it forever, since the undated entry has no year to ever be told apart by.
A contradicting year never confirms however alone the candidate is - that is exactly where a title match is a remake or a same-named sequel.

The year narrows, it never invents certainty: three of the eight "Resident Evil 2" entries are 1998, so that one still goes to the admin queue.
Verified against the live IGDB API end to end - "Resident Evil 2" 2019, "Code Vein" 2019, "Resident Evil" 2002, "God of War" 2018 and "Elden Ring" 2022 all resolve unattended to the right game, while "Resident Evil 2" 1998 and "Resident Evil 2" with no year correctly do not.

**Trade accepted, confirmed by the owner:** a title the provider spells differently no longer auto-links to whatever the search returned, and lands in the admin reconciliation queue instead.
Only a provably right match is saved, never one an admin would have had to guess at, and a user typing the correct title and year is a legitimate part of the contract for an immediate match.
The lower unattended-link rate is therefore the design rather than a regression to fix: when matching looks too strict, improve the *queries* (ask more ways, read a deeper pool, rank better) rather than loosening what counts as identity - which is exactly what the search fix above did.

Measured against the live IGDB API afterwards, each returning the canonical game first where none did before: "Code Vein" 2019, "Resident Evil" 2002 *and* 1996 (different entries), "God of War" 2018, "Elden Ring" 2022, "Mass Effect: Legendary Edition" 2021, and "Half-Life 2" (previously buried under three MMod variants).
Covered by `VideoGameReferenceClientBaseTest` over a recording fake primed with those real responses verbatim.
`ExternalProviderResilienceTest` moved to `FindGamesByExactTitleAsync`, since its subject is how many HTTP attempts one request makes and `SearchGamesAsync` is now a two-request policy.
