# Third-party provider findings

Bugs found at the boundary with TMDB, IGDB, RAWG, Discogs, Google Books, Open Library, BnF and OMDb: outages, quotas, query quirks, optional providers failing a primary operation, and how a failure is reported.
Every finding below is fixed.

## Discogs' free-text search returned albums whose title never matched, crowding out the real one and blocking automatic album linking

Found on 2026-08-05, reported from the running app: searching an album by title and artist returned results where the searched title occurred in the *artist* name rather than in any release title.

`DiscogsClient.SearchAlbumsCoreAsync` sent the title as `q=`, which is Discogs' free-text parameter - it matches the artist name, the label, credits and the tracklist, not just the release title.
`artist=` narrows the pool but doesn't constrain what `q=` matched on, and the pre-existing zero-result retry drops `artist=` entirely, leaving nothing but free text.
Confirmed directly against the real API: `q=Discovery&artist=Daft Punk` returns 5 hits, of which "Live @ Rex Club, Paris" and "MP3 Collection" carry no trace of "Discovery" in their titles;
`q=Sabbath` returns 2350 hits including releases whose only occurrence of the word is "Black Sabbath" in the artist name.

This is not cosmetic, and it is why the owner reported linking as impossible for many albums:

- `TryAutoResolveAlbumAsync` acts only on a **single** candidate (`candidates.Count != 1` returns).
  A title that free-text matches a prolific artist's back catalogue therefore never auto-resolves, however unambiguous the album itself is.
- The admin picker only ever shows the first few candidates (`ReferenceDataAdminController.MaxEnrichedCandidates`, 5), so noise ranked above the real master pushes it off the list entirely - leaving no way to link it by hand either.

Fixed by re-checking every candidate's own **parsed** release title client-side (`TitleNormalizer.LooselyContains`, whole-word containment under `NormalizeLoose`) and discarding mismatches - the same client-side re-check `BnfClient.AuthorMatches` already applies to a provider clause that isn't a strict filter.
Running it on the parsed title from `SplitArtistTitle` is what excludes a match that only ever occurred in the artist half of Discogs' combined "Artist - Title" string.
The filter lives inside `SearchAlbumsCoreAsync`, so the existing widening step needs no new condition: "the provider answered but nothing it returned is actually titled that" reaches the artist retry as the same state as an empty response.

Switching to Discogs' field-scoped `release_title=` instead was measured and rejected.
It is precise ("Sabbath" drops from 2350 hits to 209, all genuine title matches) but reorders results badly - `release_title=Nevermind&artist=Nirvana` ranks the canonical 1991 album **fourth**, behind "Nevermind Sessions" - which given the 5-candidate cap trades one failure mode for a worse one.
Filtering keeps `q=`'s relevance order and removes only what doesn't belong.

Covered by `DiscogsClientTest` (verbatim real-API response shapes, including the retry path) and `TitleNormalizerTest.LooselyContains_*`.

Files: `src/WebApi/ReferenceData/DiscogsClient.cs`, `src/Common.System/TitleNormalizer.cs`

## The guard protecting RAWG cover art fired against RAWG itself, so an admin re-linking through RAWG had the key art it just fetched thrown away

Found on 2026-08-05 while verifying that the protection added with the IGDB default (`a8fdf40`) actually holds.

The rule is right and the main case worked: `PreferredImageUrl` keeps a video game reference's stored image rather than letting a refresh overwrite it, because RAWG's `background_image` is curated landscape key art whose CDN still serves those URLs even though its API doesn't, IGDB's portrait box art is a downgrade, and the RAWG URL cannot be recomputed from the RAWG id once lost.
A reference linked through RAWG that adopts an IGDB id during the sync correctly kept its cover.

But the predicate was `externalIds.ContainsKey("rawg") && existing is not empty` - "this document carries a rawg id" as a proxy for "the stored image is a RAWG image".
Those two diverge the moment a document holds both ids, which is the normal state after `TryAdoptDefaultVideoGameProviderAsync` has run, and the proxy then inverts the rule in the one case where the operator acted deliberately:

- `ReferenceDataAdminController` passes the admin picker's provider straight into `ResolveVideoGameAsync`, which adds that provider's id to `externalIds` *before* computing the image.
  Re-linking an IGDB-covered reference through RAWG therefore made the guard fire on the rawg id it had just written, and the freshly fetched RAWG key art was discarded in favour of the stored IGDB cover.
- Which also meant a dead stored RAWG URL was unrepairable by any action short of unlinking - and unlinking deletes the shared reference document outright.
- On a `ReferenceData:VideoGameProvider=rawg` deployment the same predicate froze every reference's image permanently, RAWG included, and locked an IGDB cover in the instant a reference adopted a rawg id.

Fixed by passing the fetching client's `ProviderKey` in and exempting RAWG: every other provider still may not overwrite a stored image on a rawg-linked reference, and RAWG remains authoritative for its own data.
Covered by four `RefreshVideoGameReferenceAsync_*` cases (keeps the RAWG cover through IGDB, updates when there is no rawg id, takes a cover when none is stored, never overwrites with nothing) plus `ResolveVideoGameAsync_TakesTheRawgCover_WhenAnAdminRelinksThroughRawg`, which fails against the old predicate.
The rule had no test at all before this, which is why a one-line predicate could carry an inversion unnoticed.

## A reference the spent OMDb quota made the sync skip was stamped as enriched anyway, so it waited a full staleness window for its next chance

Reported on 2026-08-05, one day after a deployment: half the movie list showed no rating, and the admin's rating recompute answered "0 references checked, 0 items updated" however often it was clicked.

Neither symptom was what it looked like.
The recompute is a **no-op by design** here and always would have been - it re-stamps the denormalized `ReferenceRating`/`Scale`/`Source` on tenant items from what the reference document already holds, makes no provider call, and opens with `CountLinkedOnOtherRatingSourceAsync`, which returned 0 because every linked movie was correctly stamped `imdb` already.
It can never produce a rating value; the missing half was `ratings.imdb` on the *reference* documents.
The database confirmed it exactly: 1516 linked movies (999 rated, 517 not), and 509 movie references holding an imdb id, **no** imdb rating and **no** attempt stamp - i.e. references OMDb had never been asked about - against `provider_quota` showing `omdb:2026-08-04` at 1000/1000.

The bug is in the no-change short-circuit of `RefreshTvShowReferenceAsync`/`RefreshMovieReferenceAsync`.
`BackfillImdbRatingAsync` correctly declines to spend a call it can't afford (and correctly leaves `RatingsCheckedAt` unstamped, so the title isn't written off), but both callers then set `LastEnrichedAt = DateTime.UtcNow` regardless.
That marks a document the pass admittedly skipped as freshly enriched, dropping it out of `FindStaleAsync` for the whole 3-day window - so on a quota-capped day the sync stamped hundreds of references it had done nothing for, and each got its next chance three days later rather than the next morning.
Convergence proceeded in 3-day steps instead of daily, which is what left the catalogue sitting at half coverage with no admin action able to move it.

`BackfillImdbRatingAsync` now returns an `ImdbBackfillOutcome` instead of a bool, and `LastEnrichedAt` is stamped for every outcome but `Deferred`.
Two things make the deferral safe rather than a starvation risk (the failure mode `RefreshVideoGameReferenceAsync_StampsItAsChecked_WhenNoProviderIdCouldBeResolved` guards):

- **It is narrow.**
  Only a spent allowance defers - detected via `IOmdbCallBudget.IsExhausted` before the call, and re-read after it, since the allowance can also run out mid-pass (another replica, or OMDb's own "Request limit reached!" 401 writing the day off).
  A missing key or a failed request does *not* defer: neither can be retried into working, so deferring on them would pin every reference at the head of the queue permanently.
  Nor does a reference that wanted no call in the first place.
- **It is self-limiting.**
  The allowance renews at UTC midnight, so a deferred reference costs one cheap TMDB `/changes` call per pass until then, and guarantees the next affordable calls are spent on the references actually missing a rating rather than on whatever the 3-day rotation happened to surface.

The full-fetch path deliberately keeps stamping: its expensive half (details, cast, the person upserts behind it) genuinely completed, and such a reference is left holding a TMDB rating, which puts it on the cheap short-circuit path next time round.

## A book search by ISBN had no fallback when Google Books was down, and the failure blamed Keeptrack rather than the provider

Reported on 2026-08-05: an exact ISBN (`9782265002104`) failed with "Google Books search failed (Response status code does not indicate success: 502 (Bad Gateway))", which read as a regression in this codebase.

It was not one.
Google Books' **search** endpoint was returning 503 to everything, with no application code involved - reproduced directly with `curl`:

- `volumes?q=isbn:9782265002104`, `q=dune`, `q=a` (simplest possible query) → all 503, 15/15 in a burst.
- With the `fields=` partial-response parameter removed, without `maxResults`, plain `:` vs `%3a`, `&country=FR`/`US`, key in the query string vs the `X-Goog-Api-Key` header, on `www.googleapis.com` and `books.googleapis.com` → 503 every time.
- **`volumes/{id}` on the same key → 200**, and a bogus key → 400 `API key not valid`.
  So the key, the GCP project and the Books API enablement were all fine; only search was failing.

The search path's last change (`1dc91b0`, `fields=`) was ruled out by testing without it.
Two real defects were exposed underneath, though, and both are fixed.

- **An ISBN was only ever searchable through Google Books.**
  `OpenLibraryClient` and `BnfClient` accepted the `isbn` parameter and silently ignored it, so switching provider in the admin picker - the one advertised way around a provider outage - silently degraded an exact-identifier search to a fuzzy title match.
  Both now search by it (`q=isbn:` and `bib.isbn all`, each confirmed against the real API), and the ordering/fallback policy every provider shares moved into `BookReferenceClientBase` rather than being copy-pasted a third time.
  An ISBN **miss** widens to the title search instead of short-circuiting: BnF holds no record for that ISBN while Open Library resolves it in one call, and reporting "no results" for a book the same provider can find by title would make supplying an ISBN worse than leaving it blank.
- **The error text named the wrong system.**
  `ApiExceptionFilterAttribute` correctly returned 502 with an `{ error }` body, but the Blazor client used `GetFromJsonAsync`/`EnsureSuccessStatusCode`, which throws with only the status line and **discards the body** - so the API's explanation reached nobody and the admin saw this API's gateway status instead of the provider's real one.
  The filter now describes what the provider actually did (`DescribeUpstreamFailure`: returned 503, unreachable, timed out, circuit open), `ApiResponseExtensions` reads that body into an `ApiRequestException`, and `InlineReferenceLinker` names the provider and points at the picker when the domain has another one.

Covered by `BookReferenceClientBaseTest` (the shared policy, once), ISBN query-shape cases in `OpenLibraryClientTest`/`BnfClientTest`, the new message cases in `ApiExceptionFilterAttributeTest`, and `ApiResponseExtensionsTest`.

Worth knowing for the next outage: `BookProviderSearchAndLinkResourceTest` **does** cover googlebooks search+link against the live API, but `GetThroughLiveProviderAsync` skips on a 502 by design, so it goes green-by-skipping during exactly this scenario.
That is deliberate (a third-party outage must not red CI) and should not be narrowed - but it does mean no test will ever warn about a provider being down.
The entry below already recorded Google Books "returning 503s" on 2026-08-04, a day before this was reported as a regression - the same outage, seen and not recognized as one.

Files: `src/WebApi/ReferenceData/BookReferenceClientBase.cs` (new), `GoogleBooksClient.cs`, `OpenLibraryClient.cs`, `BnfClient.cs`, `IBookReferenceClient.cs`, `ReferenceDataAdminController.cs`, `src/WebApi/Filters/ApiExceptionFilterAttribute.cs`, `src/BlazorApp/Components/Shared/ApiResponseExtensions.cs` (new), `src/BlazorApp/Components/ReferenceDataAdmin/ReferenceDataAdminApiClient.cs`, `InlineReferenceLinker.razor`, `test/WebApi.UnitTests/ReferenceData/BookReferenceClientBaseTest.cs` (new), `OpenLibraryClientTest.cs`, `BnfClientTest.cs`, `test/WebApi.UnitTests/Filters/ApiExceptionFilterAttributeTest.cs`, `test/BlazorApp.UnitTests/Components/Shared/ApiResponseExtensionsTest.cs` (new)

## A third-party provider being down reported itself as a 500, and reddened CI

Confirmed on 2026-08-04: `BookProviderSearchAndLinkResourceTest` failed in CI with a 500 from `GET /api/reference-data/search?...&provider=openlibrary`, on a commit that changed nothing on that path.

The cause was entirely outside the codebase - Open Library's `search.json` was degraded again (measured directly during the investigation:
52.3s, then 503 and two 504s), past `AddBookProviderResilienceHandler`'s 40s total budget, so `Polly.Timeout.TimeoutRejectedException` escaped the controller action.
`ApiExceptionFilterAttribute` mapped it, like everything it doesn't recognize, to **500** - which claims the fault is ours and makes a provider outage indistinguishable from a defect in this API, for a caller, for a log reader, and for a test.
This is the interactive-path sibling of the Open Library finding below: that one fixed the *background* refresh discarding its work, this one fixes how the resulting failure is *reported*.

Two fixes.

- **`ApiExceptionFilterAttribute` now maps `TimeoutRejectedException`, `BrokenCircuitException` and `HttpRequestException` to 502 Bad Gateway**, logged as a warning rather than an error - a bad gateway is worth a server-side trail, but it is not this application erroring.
  Everything else still maps to 500, and argument exceptions still to 400.
  The only outbound HTTP an action makes is to the reference providers, so the classification can't catch anything else.
  Guarded by `ApiExceptionFilterAttributeTest.OnException_MapsAFailedProviderCallTo502` (one case per way the resilience pipeline gives up).
- **The test no longer pins the flakiest provider, and skips on a genuine outage rather than failing.**
  It ran only against Open Library, chosen on the belief that keyless-and-free meant reliable; Open Library is in fact the slowest endpoint any provider here calls even when healthy.
  It is now a `[Theory]` over Google Books (the deployment default, and so the provider a real user's search reaches) and BnF (keyless, quota-free, answering in under a second while the other two were down), each case skipping itself on a 502 via `ResourceTestBase.GetThroughLiveProviderAsync`/`PostNoContentThroughLiveProviderAsync`.
  Deliberately narrow: only 502 skips, so a 500 - this API failing - still fails the test.
  Verified against the real providers while Google Books itself was returning 503s: the Google Books case skipped with its reason and the BnF case linked a real reference end to end.

Files: `src/WebApi/Filters/ApiExceptionFilterAttribute.cs`, `test/WebApi.UnitTests/Filters/ApiExceptionFilterAttributeTest.cs`, `test/WebApi.IntegrationTests/Resources/ResourceTestBase.cs`, `test/WebApi.IntegrationTests/Resources/BookProviderSearchAndLinkResourceTest.cs`, `.github/workflows/ci.yaml` (`GoogleBooks__ApiKey`, previously missing from CI)

## A slow Open Library discarded every book refresh, and pinned those books at the head of the staleness queue

Confirmed in the running app on 2026-08-04: a forced sync reported `booksChecked: 7, booksUpdated: 0` while every other domain refreshed normally, and the 7 book references kept a `last_enriched_at` from the previous day.

`AddOpenLibraryRatingFallbackAsync` (`ReferenceEnrichmentService.Books.cs`) documented itself as "best-effort - a failed/empty lookup just leaves the book unrated rather than failing the resolve", but awaited `IBookRatingByIsbnLookup.GetRatingByIsbnAsync` unguarded.
Open Library's `search.json` went slow enough to blow `AddBookProviderResilienceHandler`'s 40s total timeout (measured directly: 36.4s, 40.9s, then a 503 on three consecutive calls), so `Polly.Timeout.TimeoutRejectedException` escaped `RefreshBookReferenceAsync` **after** Google Books had already returned title, synopsis, cover, language and ISBN - discarding all of it, skipping the `UpsertAsync`, and never stamping `LastEnrichedAt`.

Two consequences.
The refresh was caught per-document by `ReferenceSyncService.SyncDomainAsync` and logged, so the pass merely looked idle;
and because nothing was stamped, the same books led the staleness queue on every subsequent pass, re-paying a 40s timeout each, unable to recover for as long as Open Library stayed slow.
The identical unguarded call also sat on the interactive path (`ResolveBookAsync`), where it meant a 40s wait and then a 500 from admin manual linking and from the auto-resolve a book creation fires.

Fixed by enforcing the documented contract at that boundary: the lookup is wrapped and logged, `OperationCanceledException` still propagates (a shutdown is not a provider being unhelpful, same exclusion as the sync's own per-document catch), and the book keeps the linking provider's data.
Same rule, and the same reason, as `IOmdbClient` never throwing - an optional secondary provider must never be able to fail the primary operation.

That guard immediately surfaced the second half of the same bug, confirmed the same way: with the refresh no longer aborting, it wrote back a `Ratings` map rebuilt from the linking provider - which never carries this value - so "The Hobbit"'s stored 4.29/498 and "Psion"'s 4.5/2 were **deleted** by a refresh that simply couldn't reach Open Library.
`AddOpenLibraryRatingFallbackAsync` now takes the previously stored rating and keeps it whenever the lookup never answered (a failure, or no ISBN to ask with), while an actual "no rating for this ISBN" response still clears it - the same distinction `RebuildRatingsAsync` makes between "OMDb has nothing" and "we never asked".

Guarded by `RefreshBookReferenceAsync_KeepsTheLinkingProvidersData_WhenTheOpenLibraryRatingLookupFails`, `ResolveBookAsync_StillLinks_WhenTheOpenLibraryRatingLookupFails` (both verified to fail without the fix) and `RefreshBookReferenceAsync_ClearsAKnownRating_WhenOpenLibraryAnswersWithNoRating`.

## An over-quota OMDb key turned admin manual linking and Explore "add" into 500s, and nothing bounded the calls that got it there

OMDb's free tier is 1000 calls/day and it answers an exhausted key with an HTTP **401**, which `GetFromJsonAsync` throws for.
`AddImdbRatingAsync` is awaited unguarded inside `ResolveTvShowAsync`/`ResolveMovieAsync`, so once the day's allowance was gone every manual link and every Explore "add" failed - despite `IOmdbClient` documenting that a missing IMDb rating is never an error.
Any OMDb outage or timeout did the same thing.

Two consumers spent the key on the same 24h tick and neither could see the other: the Explore catalogue backfill was capped by a hardcoded 250 per domain (500/day whatever else was happening), while the reference sync's IMDb backfill had no cap at all.
Nothing counted calls, and once the limit was hit a pass kept firing hundreds more doomed requests, each logged individually.

Fixed by `OmdbCallBudget` (a shared daily counter in `provider_quota`, reserved atomically so several replicas can't collectively overspend), a priority split that keeps a reserve for user-facing calls, and an `OmdbClient` that returns `OmdbLookupResult` for every outcome instead of throwing - with both of OMDb's 401s writing the day off through the shared counter.
`OmdbLookupResult.Attempted` separates "OMDb has nothing for this title" from "we never asked", so a spent budget can no longer stamp a rating attempt and suppress a title for the whole re-attempt window.

## The IMDb backfill re-bought the same "no rating" answer forever, and the recompute still cost a round trip per reference when it had work to do

Two leftovers from the OMDb-budget and recompute-no-op work above, both fixed on 2026-08-03.

`BackfillImdbRatingAsync` short-circuited only on an imdb rating being *present*, so a title IMDb genuinely has nothing for had nothing to short-circuit on:
every sync pass past the 3-day staleness cutoff paid a TMDB external-ids call and an OMDb call to learn the same thing again, indefinitely, and that traffic came out of the same 1000/day allowance the rated titles need.
The Explore catalogue backfill already solved this with a per-source attempt stamp; the reference documents now carry the same `RatingsCheckedAt` map on the same 90-day window (`RatingSourceCatalog.RatingReattemptAfter`, moved out of `ExploreCatalogueRefreshService` so the two consumers share one declaration).
The window is checked before the id lookup, so both calls are skipped, and only an attempt OMDb actually answered is stamped.
Found alongside it: a full fetch rebuilt `Ratings` from TMDB and dropped a known imdb value whenever OMDb was unreachable - `RebuildRatingsAsync` now keeps it when the call never happened.

`RecomputeReferenceRatingsAsync` did nothing when nothing was mismatched, but when there *was* work it read every reference document whole (for TV, each show's entire embedded episode guide) and fired one `UpdateMany` round trip per document.
It now pages a projected `_id` + `ratings` read by id cursor and writes each page back as a single unordered `BulkWrite`: two round trips per 500 references, none per tenant item.
The distinction matters as the user base grows - the items are re-stamped server-side inside each `UpdateMany`, so more users mean more documents written, never more round trips or more memory in the API.

## BnF's own `"and (bib.author ...)"` CQL combination is not a strict intersection - candidates not actually matching the requested author silently leaked into search results

Found on 2026-07-19 (real user report: "when I search BnF it doesn't consider the author") while BnF was the second registered book provider.
Confirmed directly against the real API: a query for title "La Peste" and author "Victor Hugo" (who never wrote a book by that title) returned several genuine Victor Hugo anthologies instead of zero results, none of them actually titled "La Peste".
The same query shape correctly narrows to 69 genuine matches when the *correct* author (Albert Camus) is used, so the server-side clause isn't useless, just not trustworthy as a hard filter on its own - it appears to fall back to relevance-ranked results for the author alone when no record actually satisfies both criteria, rather than returning an empty set.
Fixed by adding a client-side post-filter (`BnfClient.AuthorMatches`, a normalized word-presence check reusing `TitleNormalizer.Normalize`) that discards any parsed candidate whose own author text doesn't actually contain every word of the requested author, instead of trusting BnF's own filtering.
Covered by `BnfClientTest.SearchBooksAsync_FiltersOutCandidatesWhoseAuthorDoesNotActuallyMatch`.

File: `src/WebApi/ReferenceData/BnfClient.cs`

## `RefreshBookReferenceAsync` only ever checked the currently-configured default provider's key, not whichever provider a reference was actually linked through

Found on 2026-07-19 while adding a second book reference provider (BnF, alongside Open Library) and letting an admin pick either one per search/link action instead of only a deployment-wide config switch.
`RefreshBookReferenceAsync` read `reference.ExternalIds.GetValueOrDefault(bookReferenceClient.ProviderKey)`, where `bookReferenceClient` was the single injected client for whichever provider `ReferenceData:BookProvider` currently names.
Once a book reference could be linked through a *different* registered provider than the current default (e.g. linked via BnF while the deployment default stays Open Library), the periodic/on-demand sync would find no id under the default's key and silently no-op that reference forever - it would never refresh again, with no error surfaced anywhere.
Fixed by resolving against every currently-registered provider's key (`BookReferenceClientRegistry.All.FirstOrDefault(c => reference.ExternalIds.ContainsKey(c.ProviderKey))`) instead of a single injected client's key.
Covered by `ReferenceEnrichmentServiceTest.RefreshBookReferenceAsync_RefreshesViaANonDefaultRegisteredProvider_WhenThatsTheOnlyOnePresent`.

File: `src/WebApi/ReferenceData/ReferenceEnrichmentService.Books.cs`

Several findings below trace back to AutoMapper's profile-wide `AllowNullDestinationValues = false` (a null source string/collection/object silently substituted with `""`/an empty collection/a blank instance).
AutoMapper itself was removed in favor of Riok.Mapperly (see `docs/archived/automapper-removal-plan.md`), which preserves nulls by default.
The entire class of gotcha these findings patched around is now structurally impossible, not just individually fixed.
The `entity is null` guards these findings added stay in place regardless: Mapperly throws on a null source, so checking before mapping is still the only correct way to turn "no document matched" into a `null` return value.
