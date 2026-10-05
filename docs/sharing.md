# Sharing

Two independent mechanisms: an anonymous read-only link to a wishlist, and directed grants exposing whole categories to other Keeptrack accounts.

## Wishlist link

A capability URL: `GET/POST /api/wishlist/shares` and `DELETE /api/wishlist/shares/{id}` (`wishlist_share`, one document per link, `token` unique), plus `GET /api/wishlist/shared/{token}`.
That last endpoint is the app's one deliberately anonymous read, backing a static-SSR `noindex` page at `/shared/wishlist/{token}`.

- The 128-bit token is the access control: there is no mail infrastructure, and a link works for recipients without an account.
- Revoking deletes one owner-scoped document.
- `SharedWishlistApiClient` is registered without `AuthenticationTokenHandler`, which would bounce an anonymous recipient to the login page.

## Collection sharing

An owner grants an account, named by its email, read-only access to whole categories of their data (`ShareController` for the owner, `SharedWithMeController` for the recipient).
A grant is a `share` document: owner, owner display name (denormalized from the claims, so the recipient's list names the sharer without a user directory), recipient email, included categories, and a label only the owner sees.

- **Granularity is the whole category**, never per item.
- **The recipient is an account, not a link**, so nothing sensitive rides in a URL.
- **Both controllers are `MemberOnly`**: a free account can neither share nor view what is shared.
- The pages sit under the profile (`/account/manage/sharing`, `/account/manage/shared-with-me`, `/account/manage/shared/{shareId}`), not in the main navigation.

### Categories come in three kinds

`ShareCategoryClassifier.KindOf` is the single place deciding how a category is presented and whether it can be copied, read by both the copy endpoint and the owner UI's grouping.

Kind         | Categories                                          | Recipient sees                                  | Copyable
-------------|-----------------------------------------------------|-------------------------------------------------|---------
`Media`      | Movies, TV shows, books, albums, video games        | The owner's list, with an "add to my collection" action | Yes
`Collection` | Collectibles, gear                                  | The owner's list, read only                     | No
`Personal`   | Cars, houses, health                                | A read-only detail view with history and metrics | No

Health is never bundled: enabling it asks through `ConfirmModal`.

### Security

- **Every read and copy goes through `ResolveGrantAsync`**: it loads the grant, checks the caller's authenticated email against `RecipientEmail`, and checks the category is included, so a share id alone never grants access.
- Emails are normalized lowercase on store and on match.
- An account whose provider yields no `email` claim (a GitHub account with a private email) cannot be matched, so the owner shares to the email the friend signs in with.
- Revoking deletes one owner-scoped document, and the recipient's next read returns nothing.

### Copy

A media copy (`POST /api/shared-with-me/{shareId}/{category}/{itemId}/copy`) builds a fresh item carrying only identity and the reference link (`SharedItemCopyService`): title, year, creator fields and `ReferenceId`.
Owned copies, rating, favorite, notes and dates stay with the owner.
Keeping `ReferenceId` makes the copy instantly linked, since reference data is shared.

- The copy applies the free-tier quota (`FreeTierQuota.CheckAsync`), like any other creation.
- The copy is idempotent: `SharedItemMatcher` (over `TitleNormalizer`) finds an item the recipient already holds, and each read page carries `AlreadyInCollectionIds` for the "In collection" badge.

### Recipient views

- Media and collection categories render through the real `InventoryList` in read-only mode, so search, sort, filters, thumbnails and the grid all work, and per-type meta rows (`Components/Inventory/Meta/*MetaRow.razor`) are shared with the owner's pages.
- Personal categories reuse the owner's own detail pages (`CarDetail`, `HouseDetail`, `HealthProfileDetail`) through a `ShareId` parameter that switches the data source to the shared endpoints and hides every edit affordance (`CanEdit => ShareId is null`).
  Thin route wrappers (`Shared{Car,House,Health}DetailPage`) own the routes and the authorization.
- Metrics reuse the same metrics services, through one generic `SharedDetailDto<TParent, TChild, TMetrics>`.
