// One-off data cleanup: ReferenceEnrichmentService.MergeMatchedAliases's dedup check compared a freshly
// computed Creator (null for the TV show/movie/video game domains - no creator dimension in their match
// key) against an already-persisted alias's Creator using strict equality. AllowNullDestinationValues =
// false (see Program.cs) means a null Creator round-trips through Mongo as an empty string "", not null -
// so on every subsequent resolve/refresh, "" != null and the existing alias was never recognized as already
// present, appending an exact duplicate {title, year, creator} entry every time. Fixed in code
// (MergeMatchedAliases now treats null and "" as equivalent), but any document already resolved/refreshed
// more than once before the fix kept the duplicates it had already accumulated.
//
// Idempotent: keeps only the first occurrence of each distinct (title, year, creator) combination per
// document (treating null and "" creator as the same key), so re-running after some documents have
// already been deduped is a safe no-op for those.
//
// Run once per environment with reference data, e.g.:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/dedupe-matched-aliases.js
function dedupe(collection) {
  let modified = 0;
  collection.find({ matched_aliases: { $exists: true } }).forEach(doc => {
    const seen = new Set();
    const deduped = [];
    (doc.matched_aliases || []).forEach(alias => {
      const key = JSON.stringify([alias.title, alias.year, alias.creator || ""]);
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(alias);
      }
    });
    if (deduped.length !== (doc.matched_aliases || []).length) {
      collection.updateOne({ _id: doc._id }, { $set: { matched_aliases: deduped } });
      modified++;
    }
  });
  print(`${collection.getName()}: deduped ${modified} document(s)`);
}

dedupe(db.tvshow_reference);
dedupe(db.movie_reference);
dedupe(db.videogame_reference);
dedupe(db.book_reference);
dedupe(db.album_reference);
