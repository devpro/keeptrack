// One-off data migration: `TvShowReference`/`MovieReference`'s `PosterUrl` property was renamed to
// `ImageUrl` (to be shared, generically-named, across all five reference domains - see CLAUDE.md's
// "Reference data now covers five domains" section), but existing `tvshow_reference`/`movie_reference`
// documents created before that rename still carry the old `poster_url` BSON field, not `image_url`.
// Without this migration, every pre-existing reference document silently loses its cover image (the new
// entity class only ever reads `image_url`) - confirmed against a real dev database where 72/87 TV show
// references and 343/353 movie references still had the old field name.
//
// Idempotent: only touches documents that have `poster_url` but not yet `image_url`, so re-running after
// some documents have already been migrated (or naturally refreshed with the new field via the periodic
// reference sync) is a safe no-op for those.
//
// Run once per environment that has reference data older than this rename, e.g.:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/migrate-poster-url-to-image-url.js
function migrate(collection) {
  const result = collection.updateMany(
    { poster_url: { $exists: true }, image_url: { $exists: false } },
    { $rename: { poster_url: "image_url" } }
  );
  print(`${collection.getName()}: migrated ${result.modifiedCount} document(s)`);
}

migrate(db.tvshow_reference);
migrate(db.movie_reference);
