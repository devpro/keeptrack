// One-off data cleanup: the `want_to_watch` flag was removed from TV shows. Watch Next drives shows
// from the tenant's own `State`/episode history (an in-progress show with a confirmed unseen episode),
// never from a want-to-watch flag - so the flag had no consuming feature for shows and was dropped
// (it stays a movie-only concept). See CLAUDE.md. The matching `tvshow_want_to_watch` partial index
// was removed from scripts/mongodb-create-index.js.
//
// This unsets the now-orphaned `want_to_watch` field on existing tvshow documents (populated by earlier
// TV Time imports mapping the export's "for_later" status, or by the removed detail-page toggle). Leaving
// the field would just be dead data the app no longer reads.
//
// Idempotent: only touches documents that still have the field, so re-running is a safe no-op.
//
// Run once per environment that has TV show data, e.g.:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unset-tvshow-want-to-watch.js
const result = db.tvshow.updateMany(
  { want_to_watch: { $exists: true } },
  { $unset: { want_to_watch: "" } }
);
print(`tvshow: unset want_to_watch on ${result.modifiedCount} document(s)`);
