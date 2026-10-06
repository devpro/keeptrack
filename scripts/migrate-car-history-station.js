// One-off data migration: a refuel's station was free text embedded in the entry (`station.brand_name`).
// It is a reference into the shared, owner-less `car_station` collection (`station_id`) after the migration.
// That collection also owns the location that was copied onto every refuel (`location.city` / `.postal_code` / `.country` / `.coordinates`).
//
// Per entry carrying a station brand name:
//   1. Find or create the car_station for (brand name, city, postal code).
//      This is the natural key and the normalization (trim + lowercase) the application uses.
//      This script and CarStationRepository therefore never disagree about what counts as the same station.
//   2. Fill any gap on an existing station from this entry, never overwrite.
//      The first entry to describe a station wins and later ones only add what is missing, like SetReferenceLinkAsync.
//   3. Point the entry at it via station_id and drop the embedded `station` sub-document.
//
// The location is removed only from Refuel entries that got a station_id.
// A refuel that named no station has nowhere to move its city to, so it keeps it and is reported below rather than silently blanked.
// Maintenance/Other entries keep their own location by design, since they have a garage and not a station.
//
// Idempotent: every step is keyed on the old `station` sub-document still being there, so a second run matches nothing.
// Run once per environment with data older than this change, then re-run mongodb-create-index.js to add the car_station unique index, for example:
//   mongosh "mongodb://localhost:27017/keeptrack_dev" scripts/migrate-car-history-station.js

function normalize(value) {
  return value === null || value === undefined ? "" : String(value).trim().toLowerCase();
}

function blankToNull(value) {
  if (value === null || value === undefined) return null;
  const trimmed = String(value).trim();
  return trimmed.length === 0 ? null : trimmed;
}

// Find-or-create by natural key, then top up whatever the station does not know yet.
function resolveStationId(brandName, location) {
  const city = blankToNull(location?.city);
  const postalCode = blankToNull(location?.postal_code);
  const country = blankToNull(location?.country);
  const coordinates = Array.isArray(location?.coordinates) && location.coordinates.length === 2
    ? location.coordinates
    : null;

  const key = {
    brand_name_normalized: normalize(brandName),
    city_normalized: normalize(city),
    postal_code: postalCode
  };

  const existing = db.car_station.findOne(key);
  if (existing) {
    const gaps = {};
    if (!existing.city && city) {
      // The city is part of the natural key, so it can only be filled in where the key already agrees.
      // It does here, both being the empty-string form.
      gaps.city = city;
      gaps.city_normalized = normalize(city);
    }
    if (!existing.country && country) gaps.country = country;
    if (!existing.coordinates && coordinates) gaps.coordinates = coordinates;
    if (Object.keys(gaps).length > 0) db.car_station.updateOne({ _id: existing._id }, { $set: gaps });
    return existing._id;
  }

  const inserted = db.car_station.insertOne({
    brand_name: String(brandName).trim(),
    city: city,
    postal_code: postalCode,
    country: country,
    coordinates: coordinates,
    brand_name_normalized: key.brand_name_normalized,
    city_normalized: key.city_normalized
  });
  return inserted.insertedId;
}

let stationsBefore = db.car_station.countDocuments({});
let linked = 0;
let locationsCleared = 0;

db.car_history
  .find({ "station.brand_name": { $nin: [null, ""] } })
  .forEach(entry => {
    const stationId = resolveStationId(entry.station.brand_name, entry.location);
    const update = { $set: { station_id: stationId }, $unset: { station: "" } };
    // Only a Refuel gives its location up, and only because the station holds it.
    // Maintenance/Other keep theirs since they have no station to inherit from, which is why this is not an unconditional unset.
    if (entry.event_type === "Refuel" && entry.location) {
      update.$unset.location = "";
      locationsCleared++;
    }
    db.car_history.updateOne({ _id: entry._id }, update);
    linked++;
  });

// The old mapper wrote a `station` sub-document for every entry, brand name included or not.
// A nameless one carries nothing and only clutters the document.
const emptied = db.car_history.updateMany(
  { station: { $exists: true } },
  { $unset: { station: "" } }
);

print(`car_history: linked ${linked} entr(y/ies) to a station, cleared ${locationsCleared} now-redundant refuel location(s), dropped ${emptied.modifiedCount} empty station sub-document(s)`);
print(`car_station: ${db.car_station.countDocuments({}) - stationsBefore} station(s) created (${db.car_station.countDocuments({})} total)`);

// Refuels that kept a location because they name no station.
// Nothing was lost, but they are the rows an admin may want to attach to a station by hand.
const orphans = db.car_history.countDocuments({ event_type: "Refuel", station_id: { $exists: false }, location: { $exists: true } });
if (orphans > 0) {
  print(`car_history: ${orphans} refuel(s) name no station and kept their own location - attach them to a station from the entry form if you want them de-duplicated`);
}
