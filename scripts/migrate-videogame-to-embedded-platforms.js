// One-off data migration: VideoGame moved from one top-level document per (owner, title, platform) to one document per (owner, title) with an embedded `platforms` array.
// See docs/collections.md's Ownership section for the rationale.
// Tracking one game across platforms, with NG+ and completion tracking, meant duplicating the whole document per platform.
//
// This migration only reshapes each document's own flat `platform`/`state`/`finished_at` into a single-element `platforms` array.
// It does NOT merge separate documents that represent the same game on different platforms.
// That consolidation, and any manual platform or playthrough clean-up, is done by hand afterward, one game at a time.
//
// `copy_type` (Physical/Digital) did not exist before, so every migrated entry defaults to "Physical".
// Individual entries are re-flipped to "Digital" by hand where wrong, like the manual consolidation above.
//
// Idempotent: it only touches documents that still have the old `platform` field and no `platforms` array yet.
// A re-run after some documents were migrated is a no-op for those.
//
// Run once per environment with pre-existing video game data, for example:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/migrate-videogame-to-embedded-platforms.js
function migrate(collection) {
  let modified = 0;
  collection.find({ platform: { $exists: true }, platforms: { $exists: false } }).forEach(doc => {
    const platformEntry = {
      platform: doc.platform || "",
      copy_type: "Physical",
      state: doc.state || "",
      playthroughs: doc.finished_at ? [{ label: "Completed", completed_at: doc.finished_at }] : [],
      is_fully_completed: false,
      fully_completed_at: null
    };

    collection.updateOne(
      { _id: doc._id },
      {
        $set: { platforms: [platformEntry] },
        $unset: { platform: "", state: "", finished_at: "" }
      }
    );
    modified++;
  });
  print(`${collection.getName()}: migrated ${modified} document(s)`);
}

migrate(db.videogame);
