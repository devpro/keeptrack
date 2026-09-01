# Code quality findings

Findings from the code review opened on 2026-07-06 against current .NET and MongoDB best practices, and from every review since.
Each one records what went wrong, how it was proven, and what was changed, so a later review does not re-report it and a later change does not undo it.
`AGENTS.md` states the rule each finding produced and links here for the evidence, so a file below is read when a specific question is open, never as background.

A finding is classified as a confirmed bug (all of which are now fixed), a confirmed by-design behaviour, or a known gap that is not yet implemented.
Add a new finding to the file its subject belongs to, and add its line here.

## [Reference matching](reference-matching.md)

The alias key, the confirmation rules, and the link surviving an edit.

- [Aliases were stored without the field that identifies the work](reference-matching.md#matched-aliases-were-stored-without-the-field-that-identifies-the-work-so-the-local-match-key-answered-questions-nobody-had-confirmed---and-the-create-path-never-asked-it-anyway)
- [Four domains resolved on "the provider returned one row"](reference-matching.md#tv-shows-movies-books-and-albums-resolved-on-the-provider-returned-exactly-one-row-which-refused-ordinary-titles-and-linked-unrelated-ones)
- [Saving any field erased the item's reference link](reference-matching.md#saving-any-field-on-a-detail-page-erased-the-items-reference-link-which-is-what-was-really-behind-it-doesnt-match-but-if-i-click-refresh-it-matches)
- [The yearless title lookup adopted an arbitrary same-titled work](reference-matching.md#the-yearless-title-only-reference-lookup-returned-whichever-same-titled-document-the-database-handed-back-first-so-an-item-with-no-year-silently-adopted-an-arbitrary-work)
- [The title-only fallback ignored a year the tenant had recorded](reference-matching.md#title-only-fallback-ignored-a-tenant-recorded-year-so-two-same-titled-but-genuinely-different-items-could-be-silently-linked-to-the-same-reference-document---or-worse-merged-into-one-via-resolveasync)

## [Video game matching](video-game-matching.md)

The hardest matching domain, and the one whose regressions kept reaching the owner.

- [Matching was tested as a rule, never as a journey](video-game-matching.md#video-game-matching-was-tested-only-as-a-rule-never-as-a-journey-so-three-regressions-in-a-row-reached-the-owner-instead-of-a-test)
- [Search dropped the year and truncated the provider's ranking](video-game-matching.md#video-game-search-dropped-the-year-on-the-floor-and-truncated-the-providers-ranking-to-five-so-a-title-matching-name-and-year-exactly-was-routinely-not-among-the-results)
- [Auto-resolution counted results instead of confirming one](video-game-matching.md#automatic-video-game-resolution-decided-on-how-many-results-the-search-returned-rather-than-on-whether-any-of-them-was-the-game)

## [Third-party providers](providers.md)

Outages, quotas, query quirks, and how a provider failure is reported.

- [Discogs' free-text search returned albums titled something else](providers.md#discogs-free-text-search-returned-albums-whose-title-never-matched-crowding-out-the-real-one-and-blocking-automatic-album-linking)
- [The RAWG cover-art guard fired against RAWG itself](providers.md#the-guard-protecting-rawg-cover-art-fired-against-rawg-itself-so-an-admin-re-linking-through-rawg-had-the-key-art-it-just-fetched-thrown-away)
- [A reference the spent OMDb quota skipped was stamped as enriched](providers.md#a-reference-the-spent-omdb-quota-made-the-sync-skip-was-stamped-as-enriched-anyway-so-it-waited-a-full-staleness-window-for-its-next-chance)
- [An ISBN search had no fallback while Google Books was down](providers.md#a-book-search-by-isbn-had-no-fallback-when-google-books-was-down-and-the-failure-blamed-keeptrack-rather-than-the-provider)
- [A provider being down reported itself as a 500, and reddened CI](providers.md#a-third-party-provider-being-down-reported-itself-as-a-500-and-reddened-ci)
- [A slow Open Library discarded every book refresh](providers.md#a-slow-open-library-discarded-every-book-refresh-and-pinned-those-books-at-the-head-of-the-staleness-queue)
- [An over-quota OMDb key turned linking and Explore "add" into 500s](providers.md#an-over-quota-omdb-key-turned-admin-manual-linking-and-explore-add-into-500s-and-nothing-bounded-the-calls-that-got-it-there)
- [The IMDb backfill re-bought the same "no rating" answer forever](providers.md#the-imdb-backfill-re-bought-the-same-no-rating-answer-forever-and-the-recompute-still-cost-a-round-trip-per-reference-when-it-had-work-to-do)
- [BnF's author clause is not a strict intersection](providers.md#bnfs-own-and-bibauthor--cql-combination-is-not-a-strict-intersection---candidates-not-actually-matching-the-requested-author-silently-leaked-into-search-results)
- [A book refresh only ever checked the default provider](providers.md#refreshbookreferenceasync-only-ever-checked-the-currently-configured-default-providers-key-not-whichever-provider-a-reference-was-actually-linked-through)

## [Sync, Explore and import](sync-explore-and-import.md)

The work that runs on a schedule or in the background.

- [Explore stopped recognising games the owner already tracks](sync-explore-and-import.md#explore-stopped-recognising-the-video-games-the-owner-already-tracks-because-both-halves-of-its-exclusion-failed-on-the-same-documents-after-the-igdb-switch)
- [Import matched by the `_id` it was exported with](sync-explore-and-import.md#reference-data-import-matched-documents-by-the-_id-they-were-exported-with-so-importing-into-a-non-empty-database-duplicated-or-failed-outright)
- [Import ran as a blocking request and always timed out](sync-explore-and-import.md#reference-data-import-ran-as-a-blocking-request-so-a-real-export-always-failed-on-the-clients-100s-http-timeout-while-the-server-kept-importing)
- [The sync read every reference document each tick](sync-explore-and-import.md#the-periodic-sync-read-every-reference-document-each-tick-and-the-admins-rating-recompute-rewrote-values-that-were-already-correct)

## [Blazor UI](blazor-ui.md)

Rendering, polling, and what a missing item looks like.

- [A page rendered itself back over the page it had navigated to](blazor-ui.md#the-home-page-painted-itself-back-over-the-page-it-was-navigated-away-from-seconds-later---the-app-bug-behind-the-playwright-suites-element-not-visible-flake)
- [A detail page's link poll overwrote what the user had just done](blazor-ui.md#the-poll-that-reveals-a-freshly-created-items-reference-link-overwrote-whatever-the-user-did-while-it-ran-and-resurrected-a-platform-that-had-just-been-removed)
- [A missing item, and a malformed id, reached the error page instead of a 404](blazor-ui.md#an-id-that-names-nothing-reached-the-user-as-the-generic-error-page-instead-of-a-404-and-an-id-that-wasnt-a-valid-objectid-reached-it-as-a-500)

## [Persistence and mapping](persistence-and-mapping.md)

MongoDB filters, indexes, and the AutoMapper null behaviour that predated Mapperly.

- [`mapper.Map<T>(null)` returned a fake empty object, base repository included](persistence-and-mapping.md#mappermaptnull-returned-a-fake-empty-object-instead-of-null---also-affected-the-shared-base-repository-not-just-the-reference-data-ones)
- [A null collection member was mapped to an empty collection](persistence-and-mapping.md#allownulldestinationvalues--false-also-substitutes-an-empty-collection-for-a-null-reference-type-member-not-just-an-empty-string)
- [`mapper.Map<T>(null)` returned a fake empty object instead of null](persistence-and-mapping.md#mappermaptnull-returned-a-fake-empty-object-instead-of-null)
- [`Eq(ReferenceId, null)` never matched, because it was never null](persistence-and-mapping.md#eqx--xreferenceid-null-never-matched-a-document-because-it-was-never-actually-null)
- [The index script had it backwards, and missed `owner_id` almost everywhere](persistence-and-mapping.md#index-script-had-it-backwards-dead-text-indexes-on-bookmovietvshowvideogame-missing-ones-on-carcarhistory-and-no-plain-owner_id-index-almost-anywhere)
- [Search was a no-op for Movie and Album](persistence-and-mapping.md#search-was-a-no-op-for-movie-and-album)
- [CarHistory treated a car id as free text](persistence-and-mapping.md#carhistory-treated-a-car-id-as-free-text-and-carrepositorys-search-never-covered-the-field-that-actually-exists-on-a-car-document)

## [Sonar](sonar.md)

What the analysis reported, what was acted on, and the standing false positives.

- [Project-wide review: S2365, ASP0025, CA1862, CA1859, JS S2486](sonar.md#project-wide-sonar-review-main-branch-not-pr-scoped-s2365-asp0025-2-ca1862-2-ca1859-3-js-s2486)
- [S107: too many parameters on the import merge service](sonar.md#s107-too-many-parameters-on-owneditemimportmergeservicecomputecommitplanmergeitem-and-amazonimportcontrollercommitasync)

## [By design, and known gaps](by-design-and-gaps.md)

Nothing here is a bug to fix.
Read it before re-reporting any of it.

- [Each entity searches its own fields](by-design-and-gaps.md#each-entity-searches-its-own-fields)
- [Open Library's search noise is left alone, on purpose](by-design-and-gaps.md#open-librarys-book-search-has-the-same-free-text-noise-as-discogs-had-and-is-deliberately-left-alone-decided-2026-08-05---read-this-before-fixing-it)
- [No `CancellationToken` propagation](by-design-and-gaps.md#no-cancellationtoken-propagation)
- [No pagination bounds](by-design-and-gaps.md#no-pagination-bounds)
- [Thin test coverage](by-design-and-gaps.md#thin-test-coverage)
