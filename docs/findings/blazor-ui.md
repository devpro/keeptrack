# Blazor UI findings

Rendering, polling and missing items in the Blazor Server app.

## A page never renders after the user navigated away

Enhanced navigation swaps the DOM to the new page while the old component is still mounted.
When the old page's slow load finishes, its render paints it back over the new page, with the address bar and sidebar still showing the new one.
`Home.razor` hit this through `/api/stats` (eleven Mongo counts), so its `ShouldRender` only renders while the browser is still on its route.
Any page whose loading can outlast a click needs the same guard.

This was the cause of the Playwright suite's "element not visible" flake.

## The pending-link watch never overwrites the user

`PendingReferenceLink` re-reads a just-created item for a few seconds to show its reference link once background resolution lands.
Replacing the page's model is risky, so it is limited:

- **It replaces the model only when the fresh read is linked.**
  Swapping the model swaps the lists a pending action holds, so removing a copy while its confirmation is open would remove nothing and the save would write it back.
- **It stops at the first save** (`MarkEdited`, called before the PUT).
- **It discards an answer if a save landed while the read was in flight**, otherwise the pre-save document comes back and the next save writes it.

`PendingReferenceLinkTest` and `ReferenceLinkedDetailPageBaseTest` cover this without a browser, since the e2e tests only hit the window by chance.

## A missing item is a 404, never the error page

- `InventoryApiClientBase.GetOneAsync` returns null for a 404 only, and every detail page renders its "not found" state from that null.
  Any other failure still throws, so an outage never looks like an empty page.
- `MongoDbRepositoryBase` treats an id that isn't a valid ObjectId as naming no document, instead of the driver's `FormatException` becoming a 500.
  This covers `DeleteAllByParentAsync` too, since the cascade runs on the raw route id.
- A detail page loads its parent before its children, and stops when the parent is null.

Known gap: a malformed id passed as a child filter (`GET /api/episodes?TvShowId=not-an-object-id`) still returns a 500.
No UI path reaches it.

## Gotchas

`PageBase.ExpectWithReloadAsync` reloads once, and only after an assertion failed, for two cases where waiting never helps:

- the URL changed but enhanced navigation never swapped the content;
- a list row shows the item before a detail page's save, which the server issues over its circuit, so the browser has nothing to wait for.
