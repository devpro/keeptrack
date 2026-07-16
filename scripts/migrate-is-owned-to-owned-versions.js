// One-off data migration: the stored `is_owned` flag was removed - ownership is now derived from
// having at least one owned copy (`owned_versions` on movie/tvshow/book/album, `platforms` on
// videogame). Existing documents flagged `is_owned: true` get one default Physical owned version
// (price/vendor/reference unknown, left unset), so nothing the user marked as owned loses that fact;
// then the obsolete flag is removed from every document.
//
// Video games get no synthesized version: their copies are their platform entries, and a platform
// can't be invented. A game flagged owned but with no platform entry is reported below so the owner
// can re-add the platform by hand - the flag alone carried no platform information anyway.
//
// Idempotent: the $set only touches documents that still have `is_owned: true` and no owned_versions
// yet, and the $unset only matches documents still carrying the field.
//
// Run once per environment with data older than this change (then re-run mongodb-create-index.js to
// replace the old is_owned partial indexes), e.g.:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/migrate-is-owned-to-owned-versions.js
function migrate(collection) {
  const seeded = collection.updateMany(
    { is_owned: true, $or: [{ owned_versions: { $exists: false } }, { owned_versions: { $size: 0 } }] },
    { $set: { owned_versions: [{ copy_type: "Physical" }] } }
  );
  const cleaned = collection.updateMany({ is_owned: { $exists: true } }, { $unset: { is_owned: "" } });
  print(`${collection.getName()}: seeded ${seeded.modifiedCount} default owned version(s), removed is_owned from ${cleaned.modifiedCount} document(s)`);
}

migrate(db.movie);
migrate(db.tvshow);
migrate(db.book);
migrate(db.album); // albums never had is_owned - harmless no-op kept for symmetry/safety

// videogame: report before unsetting, so owned-but-platformless games are visible instead of silently unowned
db.videogame
  .find({ is_owned: true, $or: [{ platforms: { $exists: false } }, { platforms: { $size: 0 } }] }, { title: 1 })
  .forEach(g => print(`videogame "${g.title}" was flagged owned but has no platform entry - re-add its platform by hand`));
const games = db.videogame.updateMany({ is_owned: { $exists: true } }, { $unset: { is_owned: "" } });
print(`videogame: removed is_owned from ${games.modifiedCount} document(s)`);
