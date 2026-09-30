# Third-party provider findings

How the code copes with TMDB, IGDB, RAWG, Discogs, Google Books, Open Library, BnF and OMDb: slow or down endpoints, quotas and query quirks.

## A provider failure is a 502, and the UI says which provider failed

A timeout, an exhausted retry or an open circuit (`TimeoutRejectedException`, `BrokenCircuitException`, `HttpRequestException`) becomes a 502, logged as a warning.
A 500 would blame this API for a provider outage.

The 502 body says what the provider did (`DescribeUpstreamFailure`), and the Blazor side reads it through `ApiResponseExtensions`.
`GetFromJsonAsync` and `EnsureSuccessStatusCode` throw away the body, so the user would only see "502 Bad Gateway".

Live-provider tests skip on a 502 and fail on anything else, so an outage never turns CI red.
The flip side is that no test warns when a provider is down.

## An optional provider never fails the main operation

Open Library's rating lookup and OMDb's IMDb rating are extras on top of the linking provider.
If one of them fails, the link or refresh still succeeds, and the rating already stored is kept.
Only a real "no rating" answer clears it.

Before this guard, a slow Open Library threw away a whole Google Books refresh.
Because nothing was stamped, those books then stayed at the head of the sync queue and hit the same 40s timeout on every pass.

`OperationCanceledException` is never swallowed, since a shutdown is not a provider failure.

## OMDb calls go through a shared daily budget

OMDb allows 1000 calls a day and answers an exhausted key with a 401.
`OmdbCallBudget` counts calls in `provider_quota` across replicas and keeps a reserve for user actions, so the background sync can't use up the day.
`OmdbClient` never throws: it returns an `OmdbLookupResult`, and its `Attempted` flag tells "OMDb has nothing" apart from "never asked".

- **A title IMDb has no rating for is remembered** (`RatingsCheckedAt`, 90 days), so the same empty answer isn't bought again on every pass.
- **A reference skipped because the budget ran out is not stamped as enriched** (`ImdbBackfillOutcome.Deferred`), so it retries the next day instead of three days later.
  Only a spent budget defers.
  A missing key or a failed request still stamps, since retrying can't fix them and would keep them at the head of the queue forever.
- The admin rating recompute never calls a provider: it only copies what references already hold onto tenant items.
  "0 updated" is correct when the ratings are missing from the references themselves.

## Book search is one policy for every provider

`BookReferenceClientBase` searches by ISBN alone, then title plus author, then title alone, and widens only when a step returns nothing.
An ISBN miss widens too: BnF may not know an ISBN that Open Library can find by title.
Google Books' search endpoint can be down for days while `volumes/{id}` still works, so a "book search is broken" report starts with a `curl`.

A refresh looks for any registered provider's key in `ExternalIds`, not only the default one's.
Otherwise a book linked through another provider would never refresh.

## A provider's free-text filter is not trusted

- **Discogs' `q=`** also matches the artist, label, credits and tracklist, so every candidate's parsed release title is checked (`TitleNormalizer.LooselyContains`).
  `release_title=` is precise but ranks badly: Nirvana's *Nevermind* comes fourth.
  The check runs inside the core search, so a list with no real title match triggers the artist retry just like an empty one.
- **BnF's `and (bib.author ...)`** falls back to author-only results when nothing matches both, so `BnfClient.AuthorMatches` checks each candidate's author.

## RAWG cover art is kept, except by RAWG itself

`PreferredImageUrl` keeps a stored cover on a RAWG-linked reference, since RAWG's landscape key art beats IGDB's box art and can't be rebuilt once lost.
RAWG is allowed to overwrite it, or re-linking through RAWG would throw away the key art it just fetched.
The fetching client's `ProviderKey` decides, because "carries a rawg id" is also true after an IGDB adoption.
