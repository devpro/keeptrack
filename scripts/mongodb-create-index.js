// Idempotent: safe to run against a fresh database or one that already has these indexes, and safe to
// re-run after this file changes. Plain createIndex() is already a no-op when an identical index exists,
// but throws IndexOptionsConflict/IndexKeySpecsConflict (codes 85/86) if an index with the same name
// exists with a different definition - ensureIndex() drops and recreates in that case instead of failing.
function ensureIndex(collection, keys, options) {
  try {
    collection.createIndex(keys, options);
  } catch (e) {
    if (e.code === 85 || e.code === 86) {
      collection.dropIndex(options.name);
      collection.createIndex(keys, options);
    } else {
      throw e;
    }
  }
}

// owner_id: every list/search query for every tenant-scoped collection filters by owner_id first: the
// single most common access pattern in the app. episode/movie/tvshow already get this for free from a
// compound index below whose leftmost field is owner_id; these collections have no such index otherwise.
ensureIndex(db.album, { owner_id: 1 }, { name: "album_owner" });
ensureIndex(db.book, { owner_id: 1 }, { name: "book_owner" });
ensureIndex(db.car, { owner_id: 1 }, { name: "car_owner" });
ensureIndex(db.car_history, { owner_id: 1 }, { name: "car_history_owner" });
ensureIndex(db.house, { owner_id: 1 }, { name: "house_owner" });
ensureIndex(db.house_history, { owner_id: 1 }, { name: "house_history_owner" });
ensureIndex(db.health_profile, { owner_id: 1 }, { name: "health_profile_owner" });
ensureIndex(db.health_record, { owner_id: 1 }, { name: "health_record_owner" });
ensureIndex(db.collectible, { owner_id: 1 }, { name: "collectible_owner" });
ensureIndex(db.gear, { owner_id: 1 }, { name: "gear_owner" });
ensureIndex(db.movie, { owner_id: 1 }, { name: "movie_owner" });
ensureIndex(db.tvshow, { owner_id: 1 }, { name: "tvshow_owner" });
ensureIndex(db.videogame, { owner_id: 1 }, { name: "videogame_owner" });
ensureIndex(db.song, { owner_id: 1 }, { name: "song_owner" });
ensureIndex(db.playlist, { owner_id: 1 }, { name: "playlist_owner" });

// car / car_history: both repositories now search via builder.Where(f => f.Name/Description.Contains(...)),
// the same regex-filter approach as Album/Book/Movie/TvShow/VideoGame, none of which use a text index either
// - a "text" index never accelerates a regex filter, so one isn't declared here. car/car_history previously
// had a car_text/car_history_text index (`{ title: "text" }`), but Car's/CarHistory's BSON documents have no
// `title` field at all (Car's searchable field is `commercial_name`; CarHistory's is `description`) - that
// index never covered anything and CarRepository/CarHistoryRepository no longer fall back to $text, so it
// was removed rather than repointed.

// house / house_history: same regex-filter search shape as car/car_history above - no text index needed here
// either, for the same reason.

// episode: enforces the (show, season, episode) natural key and makes re-imports idempotent at the database level
ensureIndex(
  db.episode,
  { owner_id: 1, tv_show_id: 1, season_number: 1, episode_number: 1 },
  { name: "episode_natural_key", unique: true }
);
// episode: supports the Watch Next "most recently watched episode per show" lookup
ensureIndex(
  db.episode,
  { owner_id: 1, tv_show_id: 1, watched_at: -1 },
  { name: "episode_last_watched" }
);

// movie / tvshow: partial indexes over the sparse favorite/want-to-watch flags (most documents are false).
// These do NOT serve a plain "all movies/shows for this owner" query (a partial index only accelerates
// queries the planner can prove only match documents inside the partial filter) - that's what the plain
// owner_id indexes above are for.
ensureIndex(
  db.movie,
  { owner_id: 1, is_favorite: 1 },
  { name: "movie_favorite", partialFilterExpression: { is_favorite: true } }
);
ensureIndex(
  db.movie,
  { owner_id: 1, want_to_watch: 1 },
  { name: "movie_want_to_watch", partialFilterExpression: { want_to_watch: true } }
);
ensureIndex(
  db.tvshow,
  { owner_id: 1, is_favorite: 1 },
  { name: "tvshow_favorite", partialFilterExpression: { is_favorite: true } }
);
ensureIndex(
  db.tvshow,
  { owner_id: 1, want_to_watch: 1 },
  { name: "tvshow_want_to_watch", partialFilterExpression: { want_to_watch: true } }
);
// album / book: same sparse-flag partial-index rationale as movie/tvshow above.
ensureIndex(
  db.album,
  { owner_id: 1, is_favorite: 1 },
  { name: "album_favorite", partialFilterExpression: { is_favorite: true } }
);
ensureIndex(
  db.book,
  { owner_id: 1, is_favorite: 1 },
  { name: "book_favorite", partialFilterExpression: { is_favorite: true } }
);
ensureIndex(
  db.collectible,
  { owner_id: 1, is_favorite: 1 },
  { name: "collectible_favorite", partialFilterExpression: { is_favorite: true } }
);
ensureIndex(
  db.gear,
  { owner_id: 1, is_favorite: 1 },
  { name: "gear_favorite", partialFilterExpression: { is_favorite: true } }
);

// movie / tvshow / book / videogame: same sparse-flag partial-index rationale as the favorite/want-to-watch
// indexes above, for the is_wishlisted flag. VideoGame has no favorite/want-to-watch flags, so this is its
// first flag index.
ensureIndex(
  db.movie,
  { owner_id: 1, is_wishlisted: 1 },
  { name: "movie_wishlisted", partialFilterExpression: { is_wishlisted: true } }
);
ensureIndex(
  db.tvshow,
  { owner_id: 1, is_wishlisted: 1 },
  { name: "tvshow_wishlisted", partialFilterExpression: { is_wishlisted: true } }
);
ensureIndex(
  db.book,
  { owner_id: 1, is_wishlisted: 1 },
  { name: "book_wishlisted", partialFilterExpression: { is_wishlisted: true } }
);
ensureIndex(
  db.videogame,
  { owner_id: 1, is_wishlisted: 1 },
  { name: "videogame_wishlisted", partialFilterExpression: { is_wishlisted: true } }
);

// movie / tvshow / book / album / videogame: the "owned" filter. There is no stored is_owned flag anymore -
// ownership is derived from owned_versions (platforms for videogame) being non-empty, which the repositories
// query as { "owned_versions.0": { $exists: true } } (the driver's SizeGt rendering). The partial filter
// matches that predicate exactly, so the planner can use these for owned-filtered list queries while the
// index stays as sparse as the old is_owned one. Re-running this script after the migration replaces the
// old same-named is_owned index definitions automatically (ensureIndex drops on conflict).
ensureIndex(
  db.movie,
  { owner_id: 1 },
  { name: "movie_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);
ensureIndex(
  db.tvshow,
  { owner_id: 1 },
  { name: "tvshow_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);
ensureIndex(
  db.book,
  { owner_id: 1 },
  { name: "book_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);
ensureIndex(
  db.album,
  { owner_id: 1 },
  { name: "album_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);
ensureIndex(
  db.videogame,
  { owner_id: 1 },
  { name: "videogame_owned", partialFilterExpression: { "platforms.0": { $exists: true } } }
);
ensureIndex(
  db.collectible,
  { owner_id: 1 },
  { name: "collectible_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);
ensureIndex(
  db.gear,
  { owner_id: 1 },
  { name: "gear_owned", partialFilterExpression: { "owned_versions.0": { $exists: true } } }
);

// background_job: transient job-progress documents (TV Time import, reference-data "sync now") polled by
// job id - MongoDB-backed (instead of in-memory) so any WebApi replica can answer a poll. TTL cleanup
// after 7 days; reads are by _id + owner check, so no other index is needed. The "lease" collection
// (single-runner election for the periodic reference sync) needs no index at all: one tiny document per
// lease name, keyed by _id.
ensureIndex(
  db.background_job,
  { created_at: 1 },
  { name: "background_job_ttl", expireAfterSeconds: 604800 }
);

// wishlist_share: one document per issued share link - an owner can hold several at once (one per
// recipient, individually revocable), so owner_id is deliberately NOT unique. The token lookup is the
// anonymous shared-view read path and stays unique (a collision is astronomically unlikely with 128
// random bits, but the invariant belongs in the database regardless).
ensureIndex(db.wishlist_share, { owner_id: 1 }, { name: "wishlist_share_owner" });
ensureIndex(db.wishlist_share, { token: 1 }, { name: "wishlist_share_token", unique: true });

// tvshow_reference / movie_reference: shared, owner-less lookup tables (see CLAUDE.md) keyed by
// matched_aliases (every (title, year) combination ever confirmed for that reference, not just its
// canonical one - see MatchedAliases/ReferenceMatchModel in CLAUDE.md), the primary automatic-match key.
// Both sub-fields of the same embedded array element are indexed together (not two separate array fields,
// which MongoDB disallows combining in one compound index) so an ElemMatch lookup on (title, year) together
// stays indexed. Non-unique deliberately - two genuinely different real-world titles/years colliding is
// exactly what the admin curation queue is for.
ensureIndex(
  db.tvshow_reference,
  { "matched_aliases.title": 1, "matched_aliases.year": 1 },
  { name: "tvshow_reference_title_year" }
);
ensureIndex(
  db.movie_reference,
  { "matched_aliases.title": 1, "matched_aliases.year": 1 },
  { name: "movie_reference_title_year" }
);
// book_reference / videogame_reference / album_reference: same shape as tvshow_reference/movie_reference
// above, keyed by their own provider's matched_aliases (Open Library, RAWG and Discogs respectively).
ensureIndex(
  db.book_reference,
  { "matched_aliases.title": 1, "matched_aliases.year": 1 },
  { name: "book_reference_title_year" }
);
ensureIndex(
  db.videogame_reference,
  { "matched_aliases.title": 1, "matched_aliases.year": 1 },
  { name: "videogame_reference_title_year" }
);
ensureIndex(
  db.album_reference,
  { "matched_aliases.title": 1, "matched_aliases.year": 1 },
  { name: "album_reference_title_year" }
);

// tvshow_reference / movie_reference: also looked up by external provider id (e.g. TMDB id) when resolving
// a title - checked first and authoritative, since two tenants resolving the exact same TMDB entry under
// different title text must reuse the same reference document, not create a duplicate (title/year matching
// alone can't guarantee that). Same shape as person_reference_tmdb_id below.
// unique + partialFilterExpression (rather than a legacy sparse index): a real TMDB id must never be
// claimed by two different reference documents (ResolveTvShowAsync/ResolveMovieAsync already look this
// up first specifically to prevent that), and the partial filter is what makes the uniqueness constraint
// safe for any document created before this field existed - MongoDB would otherwise treat every one of
// those "missing external_ids.tmdb" documents as colliding on the same null key.
// NOTE: if this fails with a duplicate-key error, a duplicate already exists (e.g. from before the
// ResolveTvShowAsync/ResolveMovieAsync id-first dedup fix - see CLAUDE.md) and must be merged/removed first.
ensureIndex(
  db.tvshow_reference,
  { "external_ids.tmdb": 1 },
  { name: "tvshow_reference_tmdb_id", unique: true, partialFilterExpression: { "external_ids.tmdb": { $exists: true } } }
);
ensureIndex(
  db.movie_reference,
  { "external_ids.tmdb": 1 },
  { name: "movie_reference_tmdb_id", unique: true, partialFilterExpression: { "external_ids.tmdb": { $exists: true } } }
);

// person_reference: actors/cast are deduplicated across every show/movie that credits them, looked up
// by external provider id (e.g. their TMDB person id), never by name - same uniqueness rationale as above.
ensureIndex(
  db.person_reference,
  { "external_ids.tmdb": 1 },
  { name: "person_reference_tmdb_id", unique: true, partialFilterExpression: { "external_ids.tmdb": { $exists: true } } }
);

// book_reference / videogame_reference / album_reference: same external-provider-id dedup rationale as
// tvshow_reference/movie_reference above, one provider each (Open Library, RAWG, Discogs).
ensureIndex(
  db.book_reference,
  { "external_ids.openlibrary": 1 },
  { name: "book_reference_openlibrary_id", unique: true, partialFilterExpression: { "external_ids.openlibrary": { $exists: true } } }
);
ensureIndex(
  db.videogame_reference,
  { "external_ids.rawg": 1 },
  { name: "videogame_reference_rawg_id", unique: true, partialFilterExpression: { "external_ids.rawg": { $exists: true } } }
);
ensureIndex(
  db.album_reference,
  { "external_ids.discogs": 1 },
  { name: "album_reference_discogs_id", unique: true, partialFilterExpression: { "external_ids.discogs": { $exists: true } } }
);

// user_preference: exactly one document per owner (upserted by owner_id, never listed) - the unique
// index is what actually guarantees that, the same way the application-level upsert-by-owner-id logic in
// UserPreferencesRepository is only "supposed to" prevent a second document.
ensureIndex(db.user_preference, { owner_id: 1 }, { name: "user_preference_owner", unique: true });
