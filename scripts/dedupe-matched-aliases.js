// One-off data cleanup of duplicate `matched_aliases` entries.
// The dedup check in ReferenceEnrichmentService.MergeMatchedAliases compared a freshly computed Creator against the persisted alias's Creator with strict equality.
// The TV show, movie and video game domains have no creator dimension in their match key, so that Creator is null.
// AllowNullDestinationValues = false (see Program.cs) makes a null Creator round-trip through Mongo as an empty string.
// So on every later resolve or refresh, "" != null, and the existing alias was never recognized as already present.
// An exact duplicate {title, year, creator} entry was appended each time.
// MergeMatchedAliases treats null and "" as equivalent, but a document resolved or refreshed more than once before that keeps the duplicates it accumulated.
//
// Idempotent: it keeps only the first occurrence of each distinct (title, year, creator) combination per document, with null and "" creator as the same key.
// A re-run after some documents are already deduped is a no-op for those.
//
// Run once per environment with reference data, for example:
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
