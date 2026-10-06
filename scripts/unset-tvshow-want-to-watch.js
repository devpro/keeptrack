// One-off data cleanup: the `want_to_watch` flag was removed from TV shows.
// Watch Next drives shows from the tenant's own `State`/episode history (an in-progress show with a confirmed unseen episode), never from a want-to-watch flag.
// The flag had no consuming feature for shows, and it stays a movie-only concept (see docs/collections.md).
// The matching `tvshow_want_to_watch` partial index is not declared in scripts/mongodb-create-index.js.
//
// This unsets the orphaned `want_to_watch` field on existing tvshow documents.
// It was populated by TV Time imports mapping the export's "for_later" status, or by the detail-page toggle.
// Leaving it would be dead data the app does not read.
//
// Idempotent: it only touches documents that still have the field.
//
// Run once per environment that has TV show data, for example:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unset-tvshow-want-to-watch.js
const result = db.tvshow.updateMany(
  { want_to_watch: { $exists: true } },
  { $unset: { want_to_watch: "" } }
);
print(`tvshow: unset want_to_watch on ${result.modifiedCount} document(s)`);
