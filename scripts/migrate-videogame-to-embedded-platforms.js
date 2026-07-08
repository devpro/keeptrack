// One-off data migration: VideoGame moved from one top-level document per (owner, title, platform) to
// one document per (owner, title) with an embedded `platforms` array - see CLAUDE.md's video game
// section for the full rationale (tracking one game across multiple platforms, with NG+/completion
// tracking, used to mean duplicating the whole document per platform).
//
// This migration only reshapes each existing document's own flat `platform`/`state`/`finished_at` into
// a single-element `platforms` array - it does NOT merge separate documents that represent the same
// game on different platforms into one. That consolidation (and any manual platform/playthrough
// clean-up) is expected to be done by hand afterward, one game at a time.
//
// `copy_type` (Physical/Digital) never existed before this change, so every migrated entry defaults to
// "Physical" - re-flip individual entries to "Digital" by hand where wrong, same as the manual
// consolidation above.
//
// Idempotent: only touches documents that still have the old `platform` field and no `platforms` array
// yet, so re-running after some documents have already been migrated is a safe no-op for those.
//
// Run once per environment with pre-existing video game data, e.g.:
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
