// One-off data cleanup: undo the reference links that were made by guessing.
//
// `ReferenceEnrichmentService.TryLinkExisting*ReferenceAsync`/`Resolve*Async` fall back to a title-only lookup when the tenant recorded no year.
// That lookup (`I*ReferenceRepository.FindByTitleAsync`) is a `FirstOrDefaultAsync` over an unsorted, unbounded match.
// When several reference documents share a title, it returned whichever one the database handed back first.
//
// Example: a yearless "Resident Evil 2" silently adopted the 2019 remake's reference, and did it again after the link was deleted.
// IGDB holds eight games named exactly "Resident Evil 2".
// With no year there is nothing to choose between them with, so nothing should have been chosen.
//
// This script finds every tenant item that is (a) linked, (b) carries no year, and (c) whose title matches MORE THAN ONE reference document.
// Those are exactly the links that could only have been a guess, and it unlinks them.
// A yearless item whose title matches exactly one reference is left alone, since that link is the answer and not a guess.
//
// It only clears a tenant item's own link (`reference_id` plus the three denormalized rating fields, the same fields the app clears on unlink).
// It never touches a `*_reference` document, so nothing shared is lost.
// Every affected item can be re-linked with a year, or from the detail page's "check for reference match".
//
// Books and albums are included for completeness but should report about 0.
// Their title lookup is also narrowed by author/artist, so a collision needs the same title AND the same creator.
//
// DRY RUN BY DEFAULT: it prints what it would unlink and changes nothing.
// Re-run with APPLY=1 to write:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unlink-yearless-ambiguous-reference-matches.js
//   APPLY=1 mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unlink-yearless-ambiguous-reference-matches.js
//
// Idempotent: once an item is unlinked it no longer matches (a), so a re-run is a no-op.

const APPLY = process.env.APPLY === "1";

// TitleNormalizer.Normalize is Trim().ToLowerInvariant().
// Kept deliberately identical, since `matched_aliases.title` is stored in exactly this form and anything else here silently matches nothing.
function normalize(value) {
  return (value || "").trim().toLowerCase();
}

// Every domain whose local lookup can fall back to title-only.
// `creatorField` is what additionally narrows that lookup where one exists (books/albums).
// The ambiguity test has to use the same key the app does, or it would report collisions the app could never have made.
const domains = [
  { items: "videogame", references: "videogame_reference", creatorField: null },
  { items: "movie", references: "movie_reference", creatorField: null },
  { items: "tvshow", references: "tvshow_reference", creatorField: null },
  { items: "book", references: "book_reference", creatorField: "author" },
  { items: "album", references: "album_reference", creatorField: "artist" }
];

let totalUnlinked = 0;
let totalKept = 0;

for (const domain of domains) {
  // Linked, and with no year to have chosen by.
  // `null` and "missing" are different in BSON and both mean "no year recorded here", the same null-or-empty trap as the unresolved-reference filters.
  const candidates = db[domain.items]
    .find({
      reference_id: { $nin: [null, ""] },
      $or: [{ year: null }, { year: { $exists: false } }]
    })
    .toArray();

  let unlinked = 0;
  let kept = 0;

  for (const item of candidates) {
    const alias = { title: normalize(item.title) };
    if (domain.creatorField) {
      alias.creator = normalize(item[domain.creatorField]);
    }

    // How many reference documents this item's title could have matched.
    // Counting past 2 is wasted work, since "more than one" is the whole question.
    const matching = db[domain.references]
      .find({ matched_aliases: { $elemMatch: alias } })
      .limit(2)
      .toArray();

    if (matching.length < 2) {
      kept++;
      continue;
    }

    const sharing = matching.map((r) => r.title + " (" + r.year + ")").join(", ");
    print(
      `  ${domain.items} ${item._id} "${item.title}" -> was linked to ${item.reference_id}` +
        ` (${matching.length}+ references share this title: ${sharing})`
    );

    if (APPLY) {
      db[domain.items].updateOne(
        { _id: item._id },
        {
          $set: { reference_id: "" },
          $unset: { reference_rating: "", reference_rating_scale: "", reference_rating_source: "" }
        }
      );
    }
    unlinked++;
  }

  totalUnlinked += unlinked;
  totalKept += kept;
  print(
    `${domain.items}: ${candidates.length} linked item(s) with no year - ` +
      `${unlinked} ${APPLY ? "unlinked" : "would be unlinked"} as ambiguous, ${kept} left alone (single unambiguous match)`
  );
}

print("");
print(
  APPLY
    ? `Done: ${totalUnlinked} guessed link(s) cleared, ${totalKept} unambiguous link(s) kept.`
    : `DRY RUN: ${totalUnlinked} guessed link(s) would be cleared, ${totalKept} unambiguous link(s) would be kept. Re-run with APPLY=1 to write.`
);
