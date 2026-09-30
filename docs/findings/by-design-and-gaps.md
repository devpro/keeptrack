# By design, and known gaps

Nothing here is a bug to fix.
Read it before reporting any of it.

## By design

### Each entity searches its own fields

`Book` searches title, series and author, `VideoGame` adds exact filters on platform and state, and `TvShow` and `Movie` search the title only.
There is no shared search contract, since each type searches the fields that make sense for it.

### Open Library's search noise is left alone

Open Library's `q=` matches descriptions and subjects too: `q=Sabbath` returns "Iron man" by Tony Iommi.
The title filter used for Discogs would work, but it is not applied (owner's call).

Book search is a ladder across three providers that widens only when a step is empty.
A filter that can empty a step changes which step answers, which could break the ISBN fallback that kept search working through a Google Books outage.

If this is ever done, the filter goes inside Open Library's own `SearchByTitleAsync`, never around the ladder, and never on the ISBN step.
Google Books and BnF already search title-only fields.

## Known gaps

### `CancellationToken` is only partly passed through

The generic CRUD path passes it end to end, and `CancellationTokenPropagationTest` proves it cancels a real MongoDB call.
`OnCreatedAsync` takes none on purpose, since the background enrichment it starts must outlive the request.

Custom repository methods, provider services and most Blazor API clients don't pass it yet.
Most run in background work, where the request's token is the wrong one, so each needs checking individually.

### `PageSize` has no upper bound

Detail pages ask for a huge page to load all of a parent's children.
A cap needs a dedicated "all children of this parent" endpoint first.

### Test coverage

- Nothing proves over HTTP that `AdminOnly` rejects a non-admin, since the integration suite has only one Firebase account, and it is an admin.
- `BookResourceTest` and `MovieResourceTest` are near copies, and a shared parameterized base would cover every resource.
