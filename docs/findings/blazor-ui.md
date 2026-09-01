# Blazor UI findings

Bugs found in the Blazor Server app itself: rendering that outlived a navigation, a poll writing over the user, and a missing item reaching the error page instead of a 404.
Every finding below is fixed.

## The home page painted itself back over the page it was navigated away from, seconds later - the app bug behind the Playwright suite's "element not visible" flake

Found on 2026-08-17, from full parallel runs that failed `CarSmokeTest`, `GearSmokeTest`, `HouseSmokeTest`, `ExploreSmokeTest`'s video game add and `HealthSmokeTest` - none of them touching the code those runs were testing.
This closes the "an inventory list row intermittently isn't visible under a full parallel run" entry triaged on 2026-07-31, which named two candidates (read latency, or an enhanced-navigation render race) and said to decide between them before changing anything.
**It is neither exactly: it is the page being navigated away *from* finishing its load and re-rendering over the page being navigated to.**

The traces show it frame by frame.
In `HealthSmokeTest`: the sidebar click at 0.57s, `GET /health` answered 200, the health page in the DOM at **0.79s** - and at **1.02s** the dashboard is back, with the URL still `/health` and the sidebar still marking Health as the active item.
`CarSmokeTest` shows the same 0.28s after its navigation, `GearSmokeTest` **5.4 seconds** after its own.
That last number is what rules the other candidates out: nothing about a lost click or a slow read puts a *different* page's content on screen five seconds later.

The mechanism is ordinary Blazor: a component renders automatically when its asynchronous initialisation completes, and `Home.razor`'s initialisation is a call to `/api/stats` - **eleven sequential Mongo counts**, so under a parallel run it is measured in seconds.
Enhanced navigation swaps the DOM to the destination while that load is still in flight and this component is still mounted, so its completion render paints the dashboard back over the destination, and nothing renders after it to undo that.
It is a user-facing bug, not a test artifact: anyone clicking a sidebar link while the home page is still loading gets thrown back to it, with the address bar and the sidebar both insisting they are somewhere else.

Fixed in the page itself - `Home.razor` overrides `ShouldRender` to render only while the browser is still on its own route (the circuit's `NavigationManager` is told about an enhanced navigation, which is exactly why the sidebar's active item moved, so it is a reliable test rather than a guess).
Same rule, and same reason, as the pending-reference poll below: **a component must never paint over a page the user has already moved on to.**

Two test-side safety nets were added alongside it, for the two shapes a re-read genuinely cannot be waited out (`PageBase.ExpectWithReloadAsync`, one reload then re-assert, only ever after the assertion has already failed):

- a navigation whose destination never renders - the browser is already on the right URL, so a reload re-fetches the page the click asked for;
- a list showing an item as it was before a detail page's save (`ListPage.ExpectRowThumbnailAsync`, `HouseSmokeTest`'s failure): that PUT is issued by the **server** over its circuit, so the browser has nothing to wait for and the row would never update itself.

## The poll that reveals a freshly created item's reference link overwrote whatever the user did while it ran, and resurrected a platform that had just been removed

Found on 2026-08-17, from `VideoGamePlatformSmokeTest` failing with the removed platform still on screen - and its trace shows why, not a flake: the removal was clicked, confirmed and saved, and the card came back.

`PendingReferenceLink.WatchAsync` re-reads the item every 1.5s for up to six attempts on any item that is not linked yet, and `FetchAsync` assigns the result to the page's whole model.
A game created without a year never links, so the poll runs its full nine seconds - which is exactly the window a user spends adding a platform to it.
A poll issued before a save and answered after it puts the **pre-save** document back into the model: the platform reappears with everything that had been set on it, and the next save writes that resurrected version to the server.

Two guards, because they cover different halves of the window (`VideoGameDetail` sets `_edited` in `SaveGameAsync`, before the PUT):

- the loop stops once the page reports changes of its own, so nothing is re-read after the first save - someone editing an item is no longer waiting to see whether a link lands, and the link still shows on the next load;
- `FetchPendingLinkAsync` throws its own answer away if a save landed while the read was in flight, which is the part the loop's guard cannot see.

Covered by `PendingReferenceLinkTest` (deterministic, no browser), since whether the e2e test hits the window at all depends on timing.

## An id that names nothing reached the user as the generic error page instead of a 404, and an id that wasn't a valid ObjectId reached it as a 500

Found on 2026-08-04 while adding a real 404 page to the Blazor app.

Two independent defects on the same path, both ending at the error page for what is only ever a stale bookmark, a hand-edited URL or a deleted item.

- **A 404 from the API threw.**
  `InventoryApiClientBase.GetOneAsync` used `GetFromJsonAsync`, whose built-in `EnsureSuccessStatusCode` makes a 404 an `HttpRequestException`.
  Every one of the eleven detail pages already renders a `<type> not found.` state from a null item, and that branch was simply unreachable:
  the throw killed the circuit on an in-app navigation, and blew up the prerender pass into `/error` on a direct load.
  Now only a 404 returns null; every other failure still throws, since an outage must not render as an empty detail page.
- **A malformed id threw deeper down, as a 500.**
  Every entity behind `MongoDbRepositoryBase` maps `_id` as an ObjectId, so the driver runs the string in an id filter through `ObjectId.Parse` and raises `FormatException` on anything that isn't 24 hex digits - which `ApiExceptionFilterAttribute` turns into a 500.
  `GET/PUT/DELETE /api/movies/not-an-object-id` all returned 500 (confirmed against a real MongoDB, and reproduced as four failing tests before the fix).
  `MongoDbRepositoryBase` now answers "names no document" for such an id, exactly as it does for a well-formed id that was never minted.
  The guard also covers `DeleteAllByParentAsync`: the controller's `OnDeletedAsync` cascade hook runs on the raw route id whether or not the parent delete matched, so the id reaches the child collection's parent-id filter too.

`TvShowDetail` needed one further fix: alone among the detail pages it queried its child collection *before* checking the parent existed, so the episode query - filtered on the same id - failed the whole page rather than letting it render "Show not found.".
Car/House/HealthProfile already had the parent-then-children order.

Still open, deliberately: a raw API caller can pass a malformed id as a *filter* (`GET /api/episodes?TvShowId=not-an-object-id`) and get a 500 from the child repository's `GetFilter`.
No UI path reaches it, and fixing it means touching each of the four child repositories rather than one shared method.
