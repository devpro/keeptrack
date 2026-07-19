# .NET 10 PersistentState prerender-flash fix

## First version

### Investigation

The flash is a prerender double-render, and it's inherent to the app's current architecture

Every page declares @rendermode InteractiveServer individually while the router (Routes.razor) stays static.
So opening an item from a list is not an in-circuit SPA navigation — it's an enhanced navigation that renders the detail page twice:

1. The server statically prerenders the detail page (prerendering is on by default).
LoadAsync (MovieDetail.razor:124-132) runs to completion server-side, so the HTML swapped into the DOM already shows the full movie content — that's the "partially displayed" page you see first.
2. Then blazor.web.js attaches the page to the SignalR circuit as a fresh component instance with no state.
Its first interactive render resets to _loading = true — the full content is briefly replaced by the "Loading…" spinner —
then LoadAsync runs again (a second round of API calls: the item, plus the reference document), and the content redraws.

So the sequence is content → spinner → content.
That's the "refresh" you're seeing.
A side effect worth knowing: every detail-page open (and every list-page load) currently hits the WebApi twice for the same data.

Why you may not have noticed before

Nothing on this branch (or in V2.1) changed navigation behavior —
I diffed the shared list/nav components and checked App.razor history; this double-render has been the architecture since the v1.1 rework.
I also ruled out FirebaseSessionRefresh (it's a passive token-refresh script, no reloads).
So your second message is probably right: it was always there, but it's grown more visible as detail pages got heavier —
LoadAsync now chains multiple sequential API calls (item + reference, and Car/House/Health also load history and metrics),
so the spinner window between the two renders is longer than it used to be.

How it can be fixed

.NET 10 added exactly the tool for this: the declarative [PersistentState] attribute.
Mark the loaded state on a detail page with it:

[PersistentState]
public MovieDto? Movie { get; set; }

Blazor then serializes the prerendered data into the page and restores it when the interactive instance attaches —
LoadAsync can skip the refetch when the state is already there.
That removes the flash (the interactive render diffs to identical DOM) and halves the API calls, while keeping prerendering's fast first paint.
It would need a small refactor per detail page (and could be applied to InventoryPageBase for lists too — they have the same double-fetch).
The alternative — disabling prerender via @(new InteractiveServerRenderMode(prerender: false)) —
also kills the flash but trades it for a blank-then-spinner first paint, so [PersistentState] is the better fit here.

Happy to implement it if you want — I'd start with one detail page (Movie) to validate the pattern, then roll it across the others and the list base.

Sources:
[Blazor prerendered state persistence (Microsoft Learn)](https://learn.microsoft.com/en-us/aspnet/core/blazor/state-management/prerendered-state-persistence),
[Prerender ASP.NET Core Razor components (Microsoft Learn)](https://learn.microsoft.com/en-us/aspnet/core/blazor/components/prerender),
[.NET 10 fixes prerendering with [PersistentState]](https://dotnet8.patrickgod.com/posts/net-10-finally-fixes-prerendering-in-blazor-with-persistentstate)

### Original pattern recap

- Convert the fields holding fetched data (`_x`, `_reference`, etc.) into public auto-properties marked [PersistentState] (public is a framework requirement).
  Keep `_loading` and everything else as private fields.
- OnParametersSetAsync: when the restored item's Id matches the route Id (and any co-fetched lists are non-null), skip LoadAsync, set _loading = false, and return; otherwise LoadAsync as before.
  Never touch explicit LoadAsync callers (refresh-reference, OnLinked, row save/delete) — they must still force a real re-fetch.
- Derived/non-serializable state (tuple-keyed dictionaries, grouped lookups, computed metrics view-models):
  persist only the raw fetched DTOs/lists, extract the derivation into a private BuildDerivedState() called from both LoadAsync and the restore path (see TvShowDetail).
- Careful with mechanical renames: `_reference` is a prefix of `_referenceEpisodesBySeason-style` fields — don't corrupt those (this bit once already in TvShowDetail).

## Limitations

### Known .NET 10 framework bug

The setup matches it exactly.

Only on watch next page, clicking on the Movies tab does nothing and I have an error in the Chrome console:

```txt
blazor.web.f7fxoh55ae.js:1
[2026-07-18T13:33:36.743Z]
Error: Connection disconnected with error 'Error: Server returned an error on close: Connection closed with an error.'.
Uncaught (in promise)
Error: Server returned an error on close: Connection closed with an error.
      at kn._processIncomingData (blazor.web.f7fxoh55ae.js:1:67187)
      at connection.onreceive (blazor.web.f7fxoh55ae.js:1:60364)
      at i.onmessage (blazor.web.f7fxoh55ae.js:1:84422).
```

**Diagnosis**:

dotnet/aspnetcore#65101 — "PersistentState crash the app if SignalR message size limit is hit".
The mechanics:

1. `[PersistentState]` serializes the whole WatchNextDto into the prerendered HTML, and the client must send that payload back to the server over SignalR when the interactive circuit takes over the page.
2. The Blazor hub's default MaximumReceiveMessageSize is 32 KB.
   When the persisted state exceeds it, the server rejects the message and closes the connection — producing exactly your console error (Server returned an error on close:
   Connection closed with an error), with no auto-reconnect and nothing at Information level in the logs. The real error (InvalidDataException: The maximum message size of 32768B was exceeded) only surfaces with detailed errors enabled.
   In the reported issue, ~100 small objects were enough.

This explains every observation that had me going in circles:

- Why only Watch Next: MoviesToWatch embeds full MovieDtos for every want-to-watch movie —
  TV Time "towatch" imports land there, so it's likely your largest payload. Your wishlist (ownership) is a smaller curated list that stays under 32 KB.
- Why the smoke test passes: it seeds 1 show + 1 movie — a few hundred bytes.
- Why clicking "does nothing" then errors: the circuit dies during the state handoff right after navigation; the tabs you see are dead prerendered HTML, and the click goes nowhere.
- Why other pages break until reload: the circuit is shared across in-app navigations — once it's dead, everything is dead until a full reload builds a fresh one.
- Why nothing is logged: the oversized-message rejection isn't logged as a circuit error at Error level.

To confirm it in 30 seconds:
view-source on /watch-next and look at the size of the <!--Blazor-...State:...--> comment near the end (I'd expect > ~43 KB of base64 ≈ 32 KB raw),
or temporarily add .AddInteractiveServerComponents(o => o.DetailedErrors = true) in src/BlazorApp/Program.cs:5 and repro — the console error will then name the 32768B limit.

**How to fix**:

Two real options, and I have a clear preference:

1. Drop `[PersistentState]` from WatchNextPage and WishlistPage only (recommended).
   Persisting an unbounded aggregate list into page HTML is the design flaw here — it also bloats every prerendered response.
   These two pages would just re-fetch on circuit start, and your new LoadingIndicator 200 ms delay-gate already prevents the spinner flash for fast loads, which was the original point of the commit.
   The detail pages persist a single bounded DTO and are fine to keep as-is.
2. Raise the limit via .AddHubOptions(o => o.MaximumReceiveMessageSize = 256 * 1024) — one line, keeps the no-refetch behavior, but the payload still grows with your collection and the cliff just moves further out.

**Update**: "the detail pages persist a single bounded DTO" turned out not to hold for TvShowDetail.
`TvShowReferenceModel.Episodes` is embedded (see CLAUDE.md's "Reference data" section) and unbounded per show,
so `[PersistentState]`-serializing `Reference` plus the raw `Episodes` list hit the exact same 32 KB SignalR ceiling for shows with many seasons/episodes.
`[PersistentState]` was reverted from `TvShowDetail.razor`
(back to plain private fields `_show`/`_reference`/`_episodes`, `OnParametersSetAsync` always calls `LoadAsync`, no restore-skip path) for the same reason it was dropped from Watch Next/Wishlist above.
The `_loaded`/`_loading` flash fix from "Fix loading flash" stays — it isn't part of the persisted-state mechanism and never caused this issue.
Movie/Book/Album/VideoGame/Car/House/HealthProfile/Playlist detail pages keep `[PersistentState]` since their persisted DTOs stay genuinely bounded (no embedded unbounded list like `Episodes`).

Sources:
[dotnet/aspnetcore#65101](https://github.com/dotnet/aspnetcore/issues/65101),
[Blazor SignalR guidance — message size](https://learn.microsoft.com/en-us/aspnet/core/blazor/fundamentals/signalr),
[Telerik KB on the 32 KB disconnect symptom](https://www.telerik.com/blazor-ui/documentation/knowledge-base/common-connection-closed)
