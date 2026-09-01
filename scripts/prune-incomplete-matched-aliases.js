// One-off data cleanup: matched_aliases entries that do not identify a work, and never should have been written.
// An alias is the local match key, since a lookup that finds one links the tenant's item to that reference without asking any provider, so an entry missing the field that identifies the work answers questions it was never confirmed for.
//
// Three sources, all fixed in code (see ReferenceAliasRule):
//   - every reference repository's UpsertAsync added the document's own (title, year) pair on every single upsert, with no creator: harmless-looking on a film, but on a book or an album that is a key claiming every author or artist at once;
//   - a resolve recorded whatever the tenant searched with, including a title with no year at all, which then matched that title under any year (IGDB holds eight games named exactly "Resident Evil 2");
//   - album aliases carried a year, so one release accumulated an entry per pressing year anyone typed.
//
// What survives, per domain:
//   tvshow / movie / videogame  title + year
//   album                       title + creator, with the year dropped (it is not part of the identity)
//   book                        title + creator, keeping the year when it has one, or any alias with an isbn
//
// Idempotent: a document already holding only complete aliases is left untouched.
// It deduplicates as it goes, since dropping the album year collapses several entries onto one (null and "" creator count as the same absence, exactly like ReferenceMatchModel.Matches).
//
// Dry run by default: it prints what it would change and writes nothing.
// Run with APPLY=1 to write:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/prune-incomplete-matched-aliases.js
//   APPLY=1 mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/prune-incomplete-matched-aliases.js

const apply = (typeof process !== "undefined" && process.env && process.env.APPLY === "1") || false;

function isBlank(value) {
  return value === null || value === undefined || String(value).trim() === "";
}

// title + year: a film, a show or a game is identified by both, and a same-titled namesake is ordinary
function titleAndYear(alias) {
  if (isBlank(alias.title) || alias.year === null || alias.year === undefined) return null;
  return { title: alias.title, year: alias.year };
}

// title + creator: one album exists as many pressings, so the year narrows nothing the artist has not settled
function titleAndCreator(alias) {
  if (isBlank(alias.title) || isBlank(alias.creator)) return null;
  return { title: alias.title, creator: alias.creator };
}

// title + creator, keeping the year when there is one (a book is republished as revisions the year tells apart, so the alias records the printing), or an isbn on its own, which names one printing outright
function bookIdentity(alias) {
  if (isBlank(alias.title)) return null;
  if (isBlank(alias.creator) && isBlank(alias.isbn)) return null;

  const kept = { title: alias.title };
  if (alias.year !== null && alias.year !== undefined) kept.year = alias.year;
  if (!isBlank(alias.creator)) kept.creator = alias.creator;
  if (!isBlank(alias.isbn)) kept.isbn = alias.isbn;
  return kept;
}

function prune(collection, keepIfComplete) {
  let changed = 0;
  let removed = 0;
  let emptied = 0;

  collection.find({ matched_aliases: { $exists: true, $ne: [] } }).forEach(doc => {
    const seen = new Set();
    const kept = [];

    (doc.matched_aliases || []).forEach(alias => {
      const complete = keepIfComplete(alias);
      if (complete === null) return;

      const key = JSON.stringify([complete.title, complete.year ?? null, complete.creator ?? "", complete.isbn ?? ""]);
      if (seen.has(key)) return;
      seen.add(key);
      kept.push(complete);
    });

    if (kept.length === (doc.matched_aliases || []).length) return;

    removed += (doc.matched_aliases || []).length - kept.length;
    changed++;
    // a document left with no alias at all is worth naming: it is still reachable by provider id, and the
    // next resolve/refresh writes a proper alias for it, but until then nothing matches it by title
    if (kept.length === 0) {
      emptied++;
      print(`  ${collection.getName()} ${doc._id} "${doc.title}" (${doc.year ?? "no year"}): no complete alias left`);
    }

    if (apply) collection.updateOne({ _id: doc._id }, { $set: { matched_aliases: kept } });
  });

  print(`${collection.getName()}: ${changed} document(s) with ${removed} incomplete/duplicate alias(es)${emptied > 0 ? `, ${emptied} left with none` : ""}${apply ? " - written" : " - dry run, nothing written"}`);
}

prune(db.tvshow_reference, titleAndYear);
prune(db.movie_reference, titleAndYear);
prune(db.videogame_reference, titleAndYear);
prune(db.album_reference, titleAndCreator);
prune(db.book_reference, bookIdentity);

if (!apply) print("Dry run. Re-run with APPLY=1 to write these changes.");
