# IGDB API notes

Field-level notes on IGDB that `IgdbClient.cs` doesn't need to be read, but a change to it might.
Authentication, the rate limit and the handler order are in `AGENTS.md`.

## Queries

Every query is an Apicalypse POST body to `https://api.igdb.com/v4/games`, with `Client-ID` and `Authorization: Bearer` headers:

```text
fields name,first_release_date,cover.image_id; search "Half-Life 2"; limit 50;
```

- `first_release_date` is a unix timestamp in seconds.
- `search` ranks by relevance and is noisy: "Half-Life 2" puts three MMod variants above the real game, which is why the exact-name query `where name ~ "..."` runs first.
- `search` can't be combined with `sort`.
- Critic rating counts are about ten times lower than user counts (8 to 27 for top games), which is why `MinCriticRatingCount` is much lower than `MinUserRatingCount`.

## Images

Only the cover is used, at `t_1080p` (810x1080, the largest size).
Every size token keeps the source's 3:4 shape, so the token only picks a resolution.

IGDB's landscape images are worse than they look:

- **`artworks` are contributed, not curated**: Red Dead Redemption 2's first one is posterised fan art at 720x720, and Baldur's Gate III's is a logo on black.
- **`screenshots` are raw game frames**, often with the HUD visible.

Neither matches RAWG's curated key art, which IGDB has no equivalent for.
That is why a stored RAWG cover is never replaced by an IGDB one.

## `game_type` replaced `category`

`game_type` says what kind of release a record is, and `0` means main game.
**Asking for `category` fails silently**: it is dropped from the response, and `where category = 0` matches nothing.
In the Explore refresh an empty pass keeps the old catalogue, so a stale field name just stops the ranking from updating, with no error.

Explore doesn't filter on `game_type`, since a well-reviewed DLC or remaster is worth suggesting.

The ids are data, so they are read from the API rather than copied from a list:

```bash
curl -s -X POST https://api.igdb.com/v4/game_types "${H[@]}" -d 'fields id,type; limit 50; sort id asc;'
```

## Not used yet

- `multiquery` and `where id = (1,2,3)` could refresh a whole sync page in one request instead of one per game.
- `similar_games` could power a "more like this" per item without the Explore ranking.
