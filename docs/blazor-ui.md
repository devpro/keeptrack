# Blazor UI

The Blazor Server app: shared page bases, list state, rendering pitfalls, and the visual conventions.

## Page bases

`InventoryPageBase<TDto>` centralizes list, paging, search and filter state and calls `InventoryApiClientBase<TDto>`.
A concrete list page supplies only its `Api` and `CloneItem`, plus an optional `ExtraQuery` override for its own filters.

Detail pages have two bases of the same kind:

- `ReferenceLinkedDetailPageBase<TDto, TReferenceDto>` for the five reference-linked types: loading, the pending-link watch, `SaveAsync`, and `ReferenceMatchControls` for the check, the unlink and the toast.
- `JournalDetailPageBase<TParent, TEntry, TMetrics>` for Car, House and Health: owner or shared loading, year tabs, and `JournalEntryModal` with its unsaved-changes check.

Each concrete page keeps its own `[PersistentState]` properties, since persisted state is keyed by the declaring component.
Other pages (Watch Next, Import, Quick Add) build on the shared `kt-*` classes in `app.css`, with their API clients in their own feature folder.

## List state lives in the URL

`?search=&page=&sort=` plus lowercase per-filter parameters, read through `[SupplyParameterFromQuery]`.
Search, filter and pagination navigate (`ApplyQueryChanges`, `ToggleFilter`, `SetFilter`) and the reload happens once in `OnParametersSetAsync`, so browser back restores the exact list position.

A new filter is a `[SupplyParameterFromQuery]` property, an `ExtraQuery` entry (API key, `IsFavorite`) and a button calling `ToggleFilter`/`SetFilter` with the URL parameter (`favorite`), never a mutate-then-`LoadAsync` handler.

`InventoryList`'s search box keeps a local copy of the text so a racing re-render cannot revert characters, and adopts an external `Search` only when it did not originate there (`OnParametersSet`).

## Rendering

### Prerender and persisted state

Every page declares `@rendermode InteractiveServer` while the router stays static, so opening a page is an enhanced navigation that renders it twice: a static prerender, then a fresh interactive instance on the circuit.
Without care, the second render resets to a spinner and fetches everything again, which shows as content, spinner, content.

Detail pages and `Home.razor` carry their fetched DTOs in `[PersistentState]` public properties (public is a framework requirement), and skip the load when the restored item's id matches the route.
Explicit reloads (the reference check, a row save or delete) always fetch again.
Derived or non-serializable state is rebuilt from the persisted DTOs rather than persisted itself.

**Persisted state must stay small**: it travels back over SignalR, whose hub rejects a message above 32 KB by closing the circuit, silently at Information level ([dotnet/aspnetcore#65101](https://github.com/dotnet/aspnetcore/issues/65101)).
The page then looks loaded but every click goes nowhere until a full reload.
So Watch Next, Wishlist and `TvShowDetail` (whose embedded episode guide grows with the show) fetch again on circuit start instead, and the delay-gated `LoadingIndicator` keeps a fast load from flashing.
Raising the hub limit only moves the cliff.

### A page never renders after the user navigated away

Enhanced navigation swaps the DOM to the new page while the old component is still mounted, so a slow load finishing later paints the old page back over the new one, with the address bar showing the new one.
`Home.razor`'s `ShouldRender` only renders while the browser is still on its route, and any page whose loading can outlast a click needs the same guard.

### The pending-link watch never overwrites the user

`PendingReferenceLink`, driven by `ReferenceLinkedDetailPageBase`, re-reads a just-created item for a few seconds to show its link once background resolution lands.

- **It replaces the model only when the fresh read is linked.**
  Replacing the model swaps the objects a pending action holds, so a copy awaiting its removal confirmation would remove nothing and be saved back.
- **It stops at the first save** (`MarkEdited`, called before the PUT).
- **It discards an answer when a save landed while the read was in flight**, or the pre-save document would come back and the next save would write it.

`PendingReferenceLinkTest` and `ReferenceLinkedDetailPageBaseTest` cover this without a browser, since end-to-end tests only hit the window by chance.

## Missing pages and missing items

`Components/Pages/NotFound.razor` is reached by `UseStatusCodePagesWithReExecute("/not-found")` on a full page load, by the Router's `NotFoundPage` in circuit, and by `NavigationManager.NotFound()`.
It carries `[ExcludeFromInteractiveRouting]` so it renders statically with the `HttpContext` available and opens no circuit, reads the original status from `IStatusCodeReExecuteFeature` (relabelling anything below 400 as 404),
and has no `[Authorize]`, which would reveal the page exists.

A missing item is a 404 at every layer:

- `InventoryApiClientBase.GetOneAsync` returns null for a 404 only, and every detail page renders its "not found" state from that null.
  Any other failure still throws, so an outage never looks like an empty page.
- `MongoDbRepositoryBase` treats an invalid ObjectId as naming no document (see [Data model](data-model.md#lookups-that-find-nothing)).
- A detail page fetches its parent **before** its children, and returns early when the parent is null.

## Components

**`SuggestInput`** offers free text with suggestions (fuel categories, gear categories, health specialties and practitioners).

- **Its menu survives the blur its own click causes** (`@onmousedown:preventDefault` on item and menu, plus `_menuMouseDown`): Blazor Server runs the `focusout` handler to completion before the click is dispatched, which no `Task.Delay` fixes.
- **Typing highlights a match immediately** (`DefaultActiveIndex`, the ARIA combobox automatic selection), so Enter completes, and an empty field highlights nothing.
- **Enter takes the highlight, Tab only one reached with the arrow keys**, since completing on Tab turns "Dr Kim" into "Dr Kimura".
  Escape drops the highlight, and there is no `preventDefault` on keydown.

## Razor gotchas

- **A `string`-typed component `[Parameter]` needs the `@` prefix.**
  `Title="_movie.Title"` binds the literal text and still compiles, since Razor infers C# only when the parameter type cannot accept a string (`Year="_movie.Year"` on `int?` works), so it is always `Title="@_movie.Title"`.
- A nested `<AuthorizeView>` needs an explicit `Context=`, as in `NavMenu.razor`.
- **A scoped `{Component}.razor.css` beats an equally specific `app.css` rule**, so check for one before assuming a shared rule applies, and a scoped selector does not reach a child component without `::deep`.

## Theme

Dark only: `App.razor` sets `data-bs-theme="dark"` statically on `<html>`, server rendered, so there is no flash.
It is never set client side, since enhanced navigation diffs the whole document and strips it.
System-ui fonts only, no webfonts.

`wwwroot/Keeptrack.BlazorApp.lib.module.js` is loaded automatically by name (never a manual `<script>` tag), and is where `blazor.addEventListener('enhancedload', ...)` re-applies client-side DOM state.

### Icons

**Icons are Unicode with text presentation** (`◈ ✓ ✕ ★ ▶ ↻ ⌂ ⚙ ♪ ◼ ▭ ▬ ◆`), never a codepoint with `Emoji_Presentation=Yes` (`⭐`, `👁`), never with U+FE0F.
A symbol that would only be a semantic near-match is dropped when the label carries the meaning.

**Inline SVG is how to grow past a glyph** (`Components/Shared/Icon.razor`, `stroke="currentColor"`), used by the sidebar and by `InventoryList`'s search icon, since geometric glyphs are indistinguishable at 16px.
Nav rows sit under three `.kt-nav-group` labels, and **Manage** is inside the `MemberOnly` block so a free account never sees an empty group.

`.kt-icon-spin` stays `display: inline-flex`, never `inline-block`, or the wrapped `<svg>` sits on the text baseline and orbits instead of spinning.

### Detail pages

**A media detail page's hero is `DetailHero.razor`**: cover on the left at 230px portrait or 260px square, fields on the right, stacking below 767px with the cover capped, and no cover meaning a single column.
Video games (`.kt-game-banner`) and gear and collectibles (`.kt-product-cover-box`, "contain") deliberately stay out of it.

**A video game's artwork is a full-width `aspect-ratio: 16 / 9` banner with `object-fit: cover`**, because 95% of stored references carry RAWG's 16:9 key art.
The distribution is counted before redesigning around an aspect ratio: `db.videogame_reference.find({}, {image_url: 1})` grouped by host.
Portrait covers are cropped hard on purpose, biased upward by `object-position: center 40%` since box art carries its title at the top.
The banner is not wrapped in a card (owner's call), and the page sits in a 920px `.kt-game-page` column so artwork, fields and platform cards share one width.

**`.kt-corner-flag` is the watched or read toggle and stays a corner flag**: it outranks Favorites, Watchlist and Wishlist, and its `--kt-success` green means *finished* where their accent blue means *flagged*.
It is a `<button>` with `aria-pressed`, and its radius is the card's inner radius (`calc(var(--kt-radius-lg) - 1px)`).

UI changes are reviewed with `MobileScreenshotTest` against real data (see [Testing](testing.md#end-to-end-tests)).
