# IGDB API notes

Field-level notes about IGDB that aren't needed to read `IgdbClient.cs`, kept here rather than in `CLAUDE.md` so they cost nothing until someone actually needs them.
The behavioural findings that *do* shape the code (Twitch token auth, the 4 req/s ceiling, Apicalypse POST bodies, no Metacritic score) live in `CLAUDE.md`'s per-provider findings section.

Everything below was confirmed against the live API on 2026-08-03 unless explicitly marked otherwise.

## Query shapes in use

All three are POST bodies to `https://api.igdb.com/v4/games` with `Client-ID` and `Authorization: Bearer` headers.

Purpose       | Body
--------------|-----
Details by id | `fields name,summary,first_release_date,genres.name,platforms.name,cover.image_id,rating,rating_count,aggregated_rating,aggregated_rating_count; where id = 1020;`
Search        | `fields name,first_release_date,cover.image_id; search "Half-Life 2"; limit 5;`
Ranked page   | `fields name,first_release_date,cover.image_id,rating,rating_count,aggregated_rating,aggregated_rating_count; where aggregated_rating_count >= 5; sort aggregated_rating desc; limit 500; offset 0;`

Notes:

- `first_release_date` is a unix timestamp in **seconds**.
- Images: see the dedicated section below - IGDB exposes three kinds and picking the wrong one is a visible regression, not a subtlety.
- `search` is relevance-ordered and genuinely noisy: "Half-Life 2" returns three MMod variants above the canonical game.
  It also cannot be combined with `sort`, which is one reason the search path applies no year filter (the other being that an edition's year routinely differs from the one a tenant typed).
- Critic counts run an order of magnitude below user counts - 8 to 27 for top titles, against thousands of user ratings for the same games - which is why `MinCriticRatingCount` and `MinUserRatingCount` are so far apart.

## Images: `cover` vs `artworks` vs `screenshots`

IGDB exposes three separate image collections per game, and they are **different shapes**:

Field         | What it is          | Shape
--------------|---------------------|------
`cover`       | Box art / packshot  | Portrait, 3:4
`artworks`    | Promotional key art | Landscape, usually 16:9
`screenshots` | In-game captures    | Landscape, usually 16:9

**The app stores a landscape screenshot**, falling back to the cover when a game has none.

That is dictated by the UI, not by preference: `VideoGameDetail.razor` renders the stored image full width capped at 320px tall, and `VideoGames.razor` passes `ItemImageShape="wide"` for a 16:9 tile - both with `object-fit: cover`.
Those layouts were built around RAWG's `background_image`, which was landscape key art.
Hand them portrait box art and the crop takes a horizontal band out of the middle and loses the title - confirmed on "Red Dead Redemption 2" and "Baldur's Gate", which is what prompted this.
Movies and TV are the opposite case and keep portrait posters.
**The shape a domain stores follows the layout that displays it, not the provider's preference.**

### `artworks` is a trap - use `screenshots`

`artworks` looks like the obvious choice for a landscape hero and is not.
It is **contributed, not curated**, and unreliable in both aspect ratio and quality.
Inspected directly:

Game                  | `artworks[0]`                                      | `screenshots[0]`
----------------------|----------------------------------------------------|-----------------
Red Dead Redemption 2 | 720x720 (**square**), posterised, dithered fan art | 1280x720, clean in-game frame
Baldur's Gate III     | 1274x720, a bare logo on a black background        | 1280x720, clean in-game frame

A square artwork in a 16:9 crop is mangled, and a logo makes a poor hero image.
Screenshots were 1280x720 in every sample and are actual game footage - the closest equivalent to RAWG's `background_image`.
Their one downside is that in-game HUD is sometimes visible (Baldur's Gate III's has a minimap and hotbar), which is the accepted trade.

**Do not "improve" this by preferring `artworks`** - that was tried first, and it is what made the detail page look worse than RAWG's, not better.

Two places deliberately use the cover instead:

- **Admin search results**: the candidate list renders a small 60x90 portrait thumb, which box art fits.
- **The top-rated ranking query** requests **no** landscape image at all.
  Explore's cards are portrait (shared with movies and TV, which use posters), so box art is the shape that actually suits them - and it keeps the one query that returns 500
  rows down to a single image id per game.

### Size tokens

Measured on the live CDN against a real cover id.
All cover tokens preserve the 3:4 aspect (IGDB scales to fit rather than letterboxing), so for a given image the token is a pure resolution choice - but the *source* image's own aspect is what
decides portrait vs landscape.

Token            | Cover (3:4 source) | Weight
-----------------|--------------------|-------
`t_cover_small`  | 90x120             | 3 KB
`t_cover_big`    | 264x352            | 16 KB
`t_cover_big_2x` | 528x704            | 52 KB
`t_720p`         | 540x720            | 55 KB
`t_1080p`        | 810x1080           | 107 KB

The app uses `t_720p` for screenshots (1280x720 from a 16:9 source) and `t_cover_big_2x` for the cover fallback.
`t_cover_big_2x` rather than plain `t_cover_big` because TMDB posters arrive as `w500`, and 264px renders visibly soft beside them in the same list.

### Possible future change: more than one image per reference

`VideoGameReferenceModel` holds a single `ImageUrl`, which is what every media type does and has been fine so far.
Storing both a cover and a screenshot would let each surface use the shape that suits it - portrait box art on Explore cards and in the admin picker, a landscape screenshot on the detail banner -
instead of one image being cropped by one of them.
That is a model/mapper/DTO change across all three layers plus the detail and list templates, so it is worth doing only if the single-image compromise starts to grate.
The data is already there: `screenshots.image_id` and `cover.image_id` come back in the same request at no extra cost.

## `game_type` (formerly `category`)

`game_type` classifies what kind of release a record is: a parent title, a DLC, a remaster, a port, and so on.
It **replaced** `category`, which older documentation and most third-party examples still describe.

Two things make this worth writing down:

- **`category` no longer exists, and IGDB does not say so.** Requesting it returns nothing at all (it is silently dropped from the response), and `where category = 0` parses fine and matches **zero** documents.
  A stale field name in a `where` therefore fails silently.
  In the Explore refresh pass this is especially quiet, because a pass that returns nothing deliberately keeps the previous catalogue rather than emptying it - so the ranking simply stops updating, with no error anywhere.
  Confirmed: `fields name,category,game_type; where id = 1020;` (Grand Theft Auto V) returns only `name` and `game_type: 0`.
- **`game_type = 0` means "main game".** Confirmed for GTA V. Filtering on it removes "Elden Ring: Shadow of the Erdtree" (DLC) and "The Last of Us Remastered" (a re-release) from the top of the critic ranking.

**Explore deliberately does not filter on it.** A DLC or a remaster is a first-class thing to track in Keeptrack, so a well-reviewed expansion is a legitimate suggestion rather than noise beside its parent, and both are freely searchable
and linkable either way (`SearchGamesAsync` applies no `where` clause at all).
The field is recorded here for a future advanced search - "main games only", "exclude ports", "show me expansions of things I own" are all one `where` clause once someone wants them.

### Enumerating the values

The ids are data, not a fixed enum, so read them from the API rather than trusting a list copied from a blog:

```bash
curl -s -X POST https://api.igdb.com/v4/game_types "${H[@]}" -d 'fields id,type; limit 50; sort id asc;'
```

Only `0` = main game is confirmed here.
The remaining ids are documented by IGDB as covering DLC, expansions, bundles, standalone expansions, mods, episodes, seasons, remakes, remasters, expanded games, ports, forks, packs and updates -
but the exact id-to-name mapping has not been checked against the live API, so run the command above before relying on a specific number.

## Things not yet explored

- **Multi-query** (`https://api.igdb.com/v4/multiquery`) and `where id = (1,2,3)` batching would let the nightly sync refresh a whole 500-document page in one request instead of 500.
  Deliberately out of scope of the IGDB migration - it reshapes `ReferenceSyncService.SyncDomainAsync`'s shared contract, so it belongs in its own change.
- `involved_companies`, `franchises`, `collections` and `similar_games` are all available and unused; `similar_games` in particular could back a per-item "more like this" without any of Explore's ranking machinery.
