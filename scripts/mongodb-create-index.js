db.book.createIndex({ title: "text" }, { name: "book_text" });
db.movie.createIndex({ title: "text" }, { name: "movie_text" });
db.tvshow.createIndex({ title: "text" }, { name: "tvshow_text" });
db.videogame.createIndex({ title: "text" }, { name: "videogame_text" });

// episode: enforces the (show, season, episode) natural key and makes re-imports idempotent at the database level
db.episode.createIndex(
  { owner_id: 1, tv_show_id: 1, season_number: 1, episode_number: 1 },
  { name: "episode_natural_key", unique: true }
);
// episode: supports the Watch Next "most recently watched episode per show" lookup
db.episode.createIndex(
  { owner_id: 1, tv_show_id: 1, watched_at: -1 },
  { name: "episode_last_watched" }
);

// movie / tvshow: partial indexes over the sparse favorite/want-to-watch flags (most documents are false)
db.movie.createIndex(
  { owner_id: 1, is_favorite: 1 },
  { name: "movie_favorite", partialFilterExpression: { is_favorite: true } }
);
db.movie.createIndex(
  { owner_id: 1, want_to_watch: 1 },
  { name: "movie_want_to_watch", partialFilterExpression: { want_to_watch: true } }
);
db.tvshow.createIndex(
  { owner_id: 1, is_favorite: 1 },
  { name: "tvshow_favorite", partialFilterExpression: { is_favorite: true } }
);
db.tvshow.createIndex(
  { owner_id: 1, want_to_watch: 1 },
  { name: "tvshow_want_to_watch", partialFilterExpression: { want_to_watch: true } }
);
