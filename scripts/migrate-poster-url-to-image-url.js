// One-off data migration: `TvShowReference`/`MovieReference`'s `PosterUrl` property was renamed to `ImageUrl`.
// The generic name is shared across all five reference domains, see docs/reference-data.md.
// `tvshow_reference`/`movie_reference` documents created before the rename still carry the old `poster_url` BSON field, not `image_url`.
// Without this migration, every such reference document silently loses its cover image, since the entity class only reads `image_url`.
// A real dev database had 72/87 TV show references and 343/353 movie references with the old field name.
//
// Idempotent: it only touches documents that have `poster_url` but not yet `image_url`.
// A re-run after some documents were migrated, or refreshed with the new field by the periodic reference sync, is a no-op for those.
//
// Run once per environment that has reference data older than this rename, for example:
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
