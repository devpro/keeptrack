// One-off data migration for the `House` schema change.
// `address`/`postal_code`/`country` were dropped, `city` became mandatory, and a mandatory `property_type` field was added (see docs/journals.md's House section).
// The MongoDB C# driver enforces C#'s `required` keyword on deserialization.
// A `house` document missing `city` or `property_type` would therefore fail to load, so this script backfills both and then drops the three retired fields.
//
// `city` cannot be reliably derived from the old free-text `address` field, and `property_type` has no prior signal at all.
// Both get a neutral placeholder ("" / "Other") rather than a guess, the "don't guess when the information isn't there" principle of the reference-data code.
// Affected houses are printed below so the owner can fill in the real values by hand.
//
// Idempotent: the $set only touches documents still missing `city`/`property_type`, and the $unset only matches documents still carrying the retired fields.
//
// Run once per environment with house data older than this change, for example:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/migrate-house-schema.js

db.house
  .find({ $or: [{ city: { $exists: false } }, { property_type: { $exists: false } }] }, { name: 1, address: 1, city: 1 })
  .forEach(h => print(`house "${h.name}" (was: ${h.address ?? "no address"}) needs its city/property type reviewed`));

// Two separate updates: a blanket $set on the combined $or filter would clobber a document that already has one of the two fields with the placeholder for the other.
const cityBackfilled = db.house.updateMany({ city: { $exists: false } }, { $set: { city: "" } });
print(`house: backfilled city on ${cityBackfilled.modifiedCount} document(s)`);

const propertyTypeBackfilled = db.house.updateMany({ property_type: { $exists: false } }, { $set: { property_type: "Other" } });
print(`house: backfilled property_type on ${propertyTypeBackfilled.modifiedCount} document(s)`);

const cleaned = db.house.updateMany(
  { $or: [{ address: { $exists: true } }, { postal_code: { $exists: true } }, { country: { $exists: true } }] },
  { $unset: { address: "", postal_code: "", country: "" } }
);
print(`house: removed retired address/postal_code/country fields from ${cleaned.modifiedCount} document(s)`);
