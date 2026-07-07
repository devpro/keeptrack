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
ensureIndex(db.book, { owner_id: 1 }, { name: "book_owner" });
ensureIndex(db.car, { owner_id: 1 }, { name: "car_owner" });
ensureIndex(db.car_history, { owner_id: 1 }, { name: "car_history_owner" });
ensureIndex(db.movie, { owner_id: 1 }, { name: "movie_owner" });
ensureIndex(db["music-album"], { owner_id: 1 }, { name: "music_album_owner" });
ensureIndex(db.tvshow, { owner_id: 1 }, { name: "tvshow_owner" });
ensureIndex(db.videogame, { owner_id: 1 }, { name: "videogame_owner" });

// car / car_history: the only two repositories that actually issue a $text query (CarRepository has no
// GetFilter override, so it falls back to MongoDbRepositoryBase's builder.Text(search); CarHistoryRepository
// calls builder.Text(...) directly) - confirmed by grepping every repository for ".Text(" usage. Book,
// Movie, MusicAlbum, TvShow, and VideoGame all search via builder.Where(f => f.Title.Contains(...)) (a
// regex filter), which a "text" index never accelerates - text indexes for those collections were removed
// here as dead weight, not carried forward.
// NOTE: CarHistoryRepository.GetFilter combines builder.Text(input.CarId) and builder.Text(search) with
// "&", and MongoDB only allows one $text expression per query - this index makes car_history searchable
// again, but a request supplying both CarId and a free-text search will still throw. That's a C# bug
// (already tracked in docs/code-quality-findings.md), not an indexing gap; fix it there, not here.
ensureIndex(db.car, { title: "text" }, { name: "car_text" });
ensureIndex(db.car_history, { title: "text" }, { name: "car_history_text" });

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

// tvshow_reference / movie_reference: shared, owner-less lookup tables (see CLAUDE.md) keyed by
// matched_titles (every normalized title variant ever confirmed for that reference, not just its
// canonical one - see MatchedTitles in CLAUDE.md) + year, the primary automatic-match key. Indexing an
// array field like matched_titles automatically creates a multikey index, so an "is this title one of the
// known variants" lookup stays indexed same as a plain equality field would. Non-unique deliberately - two
// genuinely different real-world titles/years colliding is exactly what the admin curation queue is for.
ensureIndex(
  db.tvshow_reference,
  { matched_titles: 1, year: 1 },
  { name: "tvshow_reference_title_year" }
);
ensureIndex(
  db.movie_reference,
  { matched_titles: 1, year: 1 },
  { name: "movie_reference_title_year" }
);

// tvshow_reference / movie_reference: also looked up by external provider id (e.g. TMDB id) when resolving
// a title - checked first and authoritative, since two tenants resolving the exact same TMDB entry under
// different title text must reuse the same reference document, not create a duplicate (title/year matching
// alone can't guarantee that). Same shape as person_reference_tmdb_id below.
ensureIndex(
  db.tvshow_reference,
  { "external_ids.tmdb": 1 },
  { name: "tvshow_reference_tmdb_id" }
);
ensureIndex(
  db.movie_reference,
  { "external_ids.tmdb": 1 },
  { name: "movie_reference_tmdb_id" }
);

// person_reference: actors/cast are deduplicated across every show/movie that credits them, looked up
// by external provider id (e.g. their TMDB person id), never by name
ensureIndex(
  db.person_reference,
  { "external_ids.tmdb": 1 },
  { name: "person_reference_tmdb_id" }
);
