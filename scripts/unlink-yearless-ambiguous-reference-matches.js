// One-off data cleanup: undo the reference links that were made by guessing.
//
// `ReferenceEnrichmentService.TryLinkExisting*ReferenceAsync`/`Resolve*Async` fall back to a title-only
// lookup when the tenant recorded no year, and that lookup (`I*ReferenceRepository.FindByTitleAsync`) is a
// `FirstOrDefaultAsync` over an unsorted, unbounded match. When several reference documents share a title, it
// therefore returned whichever one the database happened to hand back first.
//
// Reported from the running app: a yearless "Resident Evil 2" silently adopted the 2019 remake's reference,
// and did it again after the link was deleted. IGDB holds eight games named exactly "Resident Evil 2" - with
// no year there is nothing to choose between them with, so nothing should have been chosen.
//
// This script finds every tenant item that is (a) linked, (b) carries no year, and (c) whose title matches
// MORE THAN ONE reference document - i.e. exactly the links that could only have been a guess - and unlinks
// them. A yearless item whose title matches exactly one reference is left alone: that link is the answer, not
// a guess, and re-linking it would be pointless churn.
//
// It only ever clears a tenant item's own link (`reference_id` plus the three denormalized rating fields, the
// same fields the app itself clears on unlink). It never touches a `*_reference` document, so nothing shared
// is lost and every affected item can be re-linked - with a year, or from the detail page's "check for
// reference match" once the matching rule is fixed.
//
// Books and albums are included for completeness but should report ~0: their title lookup is additionally
// narrowed by author/artist, so a collision needs the same title AND the same creator.
//
// DRY RUN BY DEFAULT - it prints what it would unlink and changes nothing. Re-run with APPLY=1 to write:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unlink-yearless-ambiguous-reference-matches.js
//   APPLY=1 mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/unlink-yearless-ambiguous-reference-matches.js
//
// Idempotent: once an item is unlinked it no longer matches (a), so re-running is a safe no-op.

const APPLY = process.env.APPLY === "1";

// TitleNormalizer.Normalize - Trim().ToLowerInvariant(). Kept deliberately identical: `matched_aliases.title`
// is stored in exactly this form, so anything else here silently matches nothing.
function normalize(value) {
  return (value || "").trim().toLowerCase();
}

// Every domain whose local lookup can fall back to title-only. `creatorField` is what additionally narrows
// that lookup where one exists (books/albums) - the ambiguity test has to use the same key the app does, or
// it would report collisions the app could never have made.
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
  // linked, and with no year to have chosen by - `null` and "missing" are different in BSON and both mean
  // "no year recorded here", the same null-or-empty trap as the unresolved-reference filters
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

    // how many reference documents this item's title could have matched. Counting past 2 is wasted work -
    // "more than one" is the whole question.
    const matching = db[domain.references]
      .find({ matched_aliases: { $elemMatch: alias } })
      .limit(2)
      .toArray();

    if (matching.length < 2) {
      kept++;
      continue;
    }

    print(
      `  ${domain.items} ${item._id} "${item.title}" -> was linked to ${item.reference_id}` +
        ` (${matching.length}+ references share this title: ${matching.map((r) => `${r.title} (${r.year})`).join(", ")})`
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
