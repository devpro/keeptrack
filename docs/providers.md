# Providers

The third-party APIs behind reference data: what each supplies, and how the code copes with their outages, quotas and query quirks.
Credentials and how to obtain them are in [CONTRIBUTING.md](../CONTRIBUTING.md#reference-data-providers).

Domain           | Providers
-----------------|----------
TV shows, movies | TMDB, plus OMDb for IMDb ratings
Video games      | IGDB (default), RAWG
Albums           | Discogs
Books            | Google Books (default), Open Library, BnF

## Failures

- **A provider failure is a 502 that names the provider**, never a 500 (see [Architecture](architecture.md#errors)).
- **An optional provider never fails the main operation.**
  Open Library's rating lookup and OMDb's IMDb rating are extras on top of the linking provider: when one fails, the link or refresh still succeeds and the stored rating is kept, and only a real "no rating" answer clears it.
  Otherwise a slow Open Library would discard a whole Google Books refresh, and since nothing was stamped, those books would stay at the head of the sync queue and hit the same timeout on every pass.
  `OperationCanceledException` is never swallowed, since a shutdown is not a provider failure.
- A provider with no credentials is skipped: items of that type stay unlinked instead of failing.
- Live-provider tests skip on a 502 and fail on anything else, so an outage never turns CI red, and no test warns when a provider is down.

## Query rules

**An optional narrowing parameter never silently zeroes out results a broader search would find.**
`DiscogsClient` and `OpenLibraryClient` retry without the artist or author when the constrained search is empty (Discogs indexes "Artist (2)"),
and `DiscogsClient` asks with and without `year=` and unions them.

**A provider's free-text `q=` is not a title field.**
Discogs' `q=` also matches the artist, label, credits and tracklist, so `SearchAlbumsCoreAsync` drops candidates whose parsed release title fails `TitleNormalizer.LooselyContains`.
The check runs inside the core search, so a list with no real title match triggers the artist retry just like an empty one.
`release_title=` is precise but ranks badly: Nirvana's *Nevermind* comes fourth.

## Multi-provider domains

Books and video games implement `IBookReferenceClient`/`IVideoGameReferenceClient`, both `IReferenceProviderClient` with a `ProviderKey` and a `DisplayName`, resolved through `ReferenceClientRegistry<TClient>`.

- `Program.cs` registers every provider (a typed `AddHttpClient<TConcrete>` bridged through a transient `AddTransient<IBookReferenceClient>`, so handler rotation still works), and registration order is the admin picker's order.
- `ReferenceData:BookProvider`/`ReferenceData:VideoGameProvider` name the defaults, matched case-insensitively, and an admin picks any provider per action.
- A new provider needs only its class plus one registration block, since enrichment code never names a provider.
- **A book refresh checks every registered provider's key against `ExternalIds`**, or a book linked through a non-default provider would never refresh.
- **A video game refresh calls only the default provider**: a second provider exists because the first went down, and falling back would make every pass pay a retry and timeout against a dead host.

TV, movies and albums stay hard-wired to TMDB and Discogs, with provider-named DTOs and keys on purpose: swapping one is a redesign rather than configuration.

## TMDB

Covers TV shows and movies, including cast, and exposes the IMDb id OMDb needs: native on `/movie/{id}`, appended to the TV details call with `?append_to_response=external_ids`.
Its `/changes` endpoint lets the sync skip unchanged titles (see [Reference data](reference-data.md#keeping-references-fresh)).

## OMDb

Supplies IMDb ratings keyed by the IMDb id from TMDB, since IMDb has no public ratings API.
It is optional (`OmdbSettings.ApiKey` nullable): with no key, movies and TV keep their TMDB rating alone.

**The free tier is 1000 calls a day, so every call goes through `OmdbCallBudget`**: one shared document per provider and UTC day in `provider_quota` (TTL 7 days), reserved before the call with an atomic filtered upsert.
An over-count is possible and an under-count is not.
A per-process counter would let each replica spend the whole allowance, and keying by day renews it with no reset job.

- `Omdb:DailyCallBudget` (1000) and `Omdb:InteractiveReserve` (50): `Background` stops short of the reserve, so a user's action is never left unrated.
- **`OmdbClient` never throws for anything OMDb or the network can do**: it returns an `OmdbLookupResult`, and both 401s (limit reached, rejected key) mark the day spent for every replica.
  An unguarded throw would turn admin linking and Explore's add into 500s on an over-quota day.
- **`OmdbLookupResult.Attempted` decides stamping**: "answered with nothing" is recorded, "never asked" leaves no stamp.
- **A title IMDb has no rating for is remembered** (`RatingsCheckedAt` per source, 90 days), checked before the id lookup, carried over on re-resolve, and ignored by interactive paths, so the same empty answer is not bought on every pass.
- **A backfill the spent quota skipped does not stamp `LastEnrichedAt`** (`ImdbBackfillOutcome.Deferred`), so it retries the next day instead of a staleness window later.
  A missing key or a failed request still stamps, since retrying cannot fix them and would keep them at the head of the queue forever.
- The `/changes` short-circuit would skip the IMDb backfill forever, so `BackfillImdbRatingAsync` resolves the IMDb id cheaply through `/{tv,movie}/{id}/external_ids` on the no-change path.
- `RebuildRatingsAsync` keeps the known IMDb value when the call never happened, since a full fetch rebuilds `Ratings` from TMDB alone.

## IGDB

The default video game provider, a plain typed `HttpClient` with three differences handled around it.

- It authenticates with a **Twitch app access token**: `IgdbTokenProvider` caches one per process (a token is not a shared quota, unlike OMDb's budget),
  and `IgdbAuthenticationHandler` attaches `Client-ID` plus the bearer and retries once on a 401 with a fresh token.
  The renewal margin is capped at half the token's lifetime, or every call would fetch a new token.
- It allows **4 requests a second**, paced by a `TokenBucketRateLimiter` in a singleton (`IgdbRateLimiter`), since `IHttpClientFactory` rebuilds handlers on rotation.
- **Handler order is authentication, then resilience, then the rate limiter, outermost first.**
  The limiter sits innermost so its queue wait counts against the resilience total timeout (`HttpClient.Timeout` is infinite), and its bounded queue's synthesized 429 is retried with backoff.
- Missing credentials are supported (`IgdbSettings.IsConfigured`): every call returns an empty result.

### Queries

Every query is an Apicalypse POST body to `https://api.igdb.com/v4/games`, so a tenant title is escaped before being embedded in a string literal:

```text
fields name,first_release_date,cover.image_id; search "Half-Life 2"; limit 50;
```

- `first_release_date` is a unix timestamp in **seconds**.
- `search` ranks by relevance and is noisy ("Half-Life 2" puts three MMod variants above the real game), which is why the exact-name query `where name ~ "..."` runs first.
- `search` cannot be combined with `sort`.
- Critic rating counts are about ten times lower than user counts (8 to 27 for top games), which is why `MinCriticRatingCount` is much lower than `MinUserRatingCount`.
- It reports no Metacritic score, and `aggregated_rating` gets its own `igdbcritic` key.

**Gotcha: a stale field name fails silently.**
`game_type` says what kind of release a record is (`0` is a main game) and replaced `category`, which is now dropped from the response, so `where category = 0` parses and matches nothing.
In the Explore refresh an empty pass keeps the old catalogue, so a stale field just stops the ranking from updating, with no error.
The ids are data, read from the API rather than copied from a list:

```bash
H=(-H "Client-ID: $IGDB_CLIENT_ID" -H "Authorization: Bearer $IGDB_TOKEN")
curl -s -X POST https://api.igdb.com/v4/game_types "${H[@]}" -d 'fields id,type; limit 50; sort id asc;'
```

### Images

Only the cover is used, at `t_1080p` (810x1080, the largest size): `https://images.igdb.com/igdb/image/upload/t_1080p/{image_id}.jpg`.
Every size token keeps the source's 3:4 shape, so the token only picks a resolution.

Its landscape images are not usable as key art: `artworks` are contributed rather than curated (Red Dead Redemption 2's first one is posterised fan art at 720x720, Baldur's Gate III's a logo on black),
and `screenshots` are raw game frames, often with the HUD visible.

## RAWG

Stays registered for admin search, and so its stored `rawg`/`metacritic` values keep rendering.

**A stored cover on a RAWG-linked reference is never overwritten by another provider** (`PreferredImageUrl`): RAWG's curated landscape key art still serves from its CDN, beats IGDB's box art, and cannot be rebuilt once lost.
RAWG itself may overwrite it, or re-linking through RAWG would discard the key art it just fetched.
The fetching client's `ProviderKey` decides, because "carries a rawg id" is also true after an IGDB adoption.

**A provider only overwrites its own sources' ratings** (`MergeProviderRatings`, keyed on `SupportedRatingSources`), and a source it owns but no longer reports is dropped.

## Discogs

Albums, with the `q=` filtering and year union described in [Query rules](#query-rules).

## Google Books

The book default: synopses, covers, language, and the widest catalogue, manga included.
It queries `intitle:`/`inauthor:`, with an `isbn` as the sole query when given, and serves no ratings (see [Ratings](reference-data.md#ratings)).

- Its `volumes?q=` endpoint can be down for days while `volumes/{id}` answers, so a "book search is broken" report starts with a `curl` of the search endpoint.
- **`volumes?q=` can also answer 200 with `totalItems: 0` for `intitle:` queries, with a valid key.**
  `intitle:Dune`, `intitle:Hamlet` and `intitle:Neuromancer` returned nothing while `intitle:Harry Potter` returned 22 results, and the plain `Dune` and `inauthor:Frank Herbert` kept answering.
  The `isbn:` and `subject:` operators returned nothing as well, and one call answered 503.
  Nothing announced a change, so it reads as a degraded search index and not a quota or key problem (a keyless call answers 429 for quota).
  Book matching then links nothing, and `ReferenceMatchResourceTest`'s book cases fail with "linked null" after their 90 second poll.
  The check is a `curl` of `intitle:Dune` against the plain `Dune` with the same key: when only the first is empty, the provider is at fault and the repository is not.
- `CleanDescription` decodes entities **first**, converts newlines to `<br/>`, then rebuilds only bare `b`/`i`/`br` tags and strips everything else, which is what makes `BookDetail.razor`'s `MarkupString` safe:
  **a `MarkupString` is never rendered from text that has not been through it.**
- Thumbnails are upgraded to `https://` against mixed-content blocking.

## Open Library

- It never sends `year` as a filter, since `first_publish_year` is the work's original year.
- It searches `q=` rather than `title=`, which misses regional variants.
- `GetBookDetailsAsync` falls back to a `q=key:{workKey}` re-query when the work JSON lacks `first_publish_date`.
- It exposes no reliable series, so `BookModel.Series` is not filled automatically.
- Its search is the slowest endpoint here (tens of seconds, and 503s), so the rating fallback (`AddOpenLibraryRatingFallbackAsync`) catches everything but `OperationCanceledException` and keeps the stored rating when the lookup never answered.

**Its `q=` noise is left alone (owner's call).**
`q=` matches descriptions and subjects too (`q=Sabbath` returns "Iron man" by Tony Iommi), and the Discogs title filter would work, but book search is a ladder that widens only on an empty step.
A filter that empties a step changes which step answers, and could break the ISBN fallback that kept search working through a Google Books outage.
If it is ever done, the filter goes inside Open Library's own `SearchByTitleAsync`, never around the ladder, and never on the ISBN step.
Google Books and BnF already search title-only fields.

## BnF

The one XML/SRU client.
Its `ExternalId` is the bare ARK, its records carry no cover art, and `dc:creator` "LastName, FirstName (dates). Role" is normalized to "FirstName LastName".
Its `and (bib.author ...)` clause falls back to author-only results when nothing matches both, so `BnfClient.SearchBooksCoreAsync` re-checks each candidate's author (`AuthorMatches`).
