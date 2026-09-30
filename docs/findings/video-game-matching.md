# Video game matching findings

Video games are the hardest matching domain: catalogues are full of same-titled works, remakes, editions and DLC.
Read these before loosening how a game is matched to its reference.

## A year is required for any automatic link

`TryAutoResolveVideoGameAsync` returns without a year, and the domain has no title-only local fallback (owner's rule).
IGDB holds eight games named exactly "Resident Evil 2", so a bare title identifies nothing.

"Check for reference match" escalates to the provider when nothing local matches (`LinkVideoGameReferenceAsync`), so an item created without a year still links once the year is added.
The other four domains don't escalate, since their auto-resolve fires on "the provider returned one result" and would link something nobody compared.

Editing a field never searches by itself: the button is the only thing that re-resolves.

## A link is confirmed by name and year, never by counting results

`candidates.Count == 1` is a property of the search, not of the answer.
It links what it never compared (IGDB answers "NieR:Automata" with only "Untitled NieR:Automata Project") and refuses every title with namesakes.

`VideoGameMatchRules.ConfirmedMatches` links a candidate named this game and agreeing on the year.
It keeps only the best year tier reached, so an undated namesake never blocks the matching-year one, and a contradicting year never confirms however alone the candidate is.

A title the provider spells differently goes to the admin queue rather than auto-linking (owner's call).
When matching looks too strict, improve the queries, never loosen what counts as identity.

## Search asks for the exact title, reads a deep pool, and ranks it itself

`VideoGameReferenceClientBase` (shaped like `BookReferenceClientBase`) runs `FindGamesByExactTitleAsync`, unions a 50-deep relevance pool, then ranks.

- **Provider relevance is never a ranking key**: IGDB ranks the 2019 "Code Vein" sixth behind its sequel and DLC, so a 5-result window loses it.
- `OrderByBestMatch` ranks by names-the-work, year, title distance (an edition or DLC is the game plus something), then title.
- **The year is three-state**: requested, not reported, contradicting.
  Treating "unknown" as a contradiction discards a dateless right answer, treating it as agreement floats a dateless namesake above the real match.
- **The year is never sent as a filter**, so a wrong year costs a place in the list, not the result.
- `VideoGameMatchRules` is the single definition of "is this candidate that game", shared by search, auto-resolution and adoption.

## Gotchas

- **A title typed without its punctuation misses the exact-name query**: "code vein season pass" is found only through the relevance pool plus loose confirmation,
  which a unit test feeding `ConfirmedMatches` directly cannot see.
- **A leftover reference makes an escalation test pass falsely**, since the local lookup answers instead of the provider.
  `VideoGameReferenceMatchSmokeTest` deletes every reference it causes (`End2EndFixture.RemoveVideoGameReferencesAsync`), and `RefreshReferenceResourceTest` asserts its premise up front.
