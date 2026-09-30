# Persistence and mapping findings

MongoDB filters, indexes and object mapping.
None of these can be caught by a mocked repository, only by a test against real MongoDB.

## A lookup that can find nothing checks for null before mapping

Mapperly throws on a null source, so every `Find*Async` checks `entity is null` before mapping, `MongoDbRepositoryBase.FindOneAsync` included.
Without the check, "not found" becomes an exception instead of a 404.

## "Not linked yet" is null or empty

Documents written before Mapperly store `ReferenceId` as `""`, never null, so `Eq(x => x.ReferenceId, null)` matches none of them.
An "is this field unset" query copies `UnresolvedFilter()` from `TvShowRepository`/`MovieRepository`, which matches both.

## Search uses a regex, never `$text`

Every `GetFilter` searches with `Contains`, which a `text` index never speeds up, so the index script declares no text index.

- **MongoDB allows one `$text` per query**, so a child's parent id is filtered with `Eq`, never `Text`.
- **A `$text` filter rejects a collation**, and the title sort attaches one.
- **An index names the stored field**: `Car.Name` is stored as `commercial_name`, so an index on `title` covers nothing.
- **A `GetFilter` override combines with `filter &=`**, or its condition is built and silently dropped.

## Every tenant collection needs a plain `owner_id` index

Every list query filters on `owner_id` first.
A partial index such as `movie_favorite` doesn't help a plain list query, since the planner can only use it when the query repeats the partial filter.
