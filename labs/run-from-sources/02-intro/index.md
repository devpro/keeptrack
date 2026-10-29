# Keeptrack

Save and review everything read, watched, listened to or played.

---

## What it tracks

- **Media**: movies, TV shows, books, albums and video games, linked to provider data (covers, synopses, cast, ratings).

- **Collections**: playlists, gear, collectibles, owned copies and a wishlist shareable through an anonymous link.

- **Journals**: car, house and health, with their costs and metrics.

- **Discovery**: Watch Next for the shows in progress, Explore for the top-rated titles not tracked yet.

- **Imports**: TV Time, Amazon orders and store transaction exports.

---

## Architecture

![BlazorApp serves the browser and calls WebApi, which stores in MongoDB and reads reference data from providers](../assets/architecture-dark.svg#gh-dark-mode-only)
![BlazorApp serves the browser and calls WebApi, which stores in MongoDB and reads reference data from providers](../assets/architecture.svg#gh-light-mode-only)

---

## Signing in

Mode                 | Sign-in                                        | For
---------------------|------------------------------------------------|--------------------------------------
`Firebase` (default) | GitHub or Google, through Firebase             | Production
`Local`              | An email and a role on a form, **no password** | Local runs, tests, isolated platforms

- `BlazorApp` signs a JWT with a key it shares with `WebApi`, so nothing outside the machine is reached.

- `Local` **refuses to start** in the `Production` environment, since anyone reaching the form can sign in as anyone.

- The role picks the tier: free preview (movies and TV shows), member (everything) or admin (reference data pages too).

---

## Source-available

- The code is public on [github.com/devpro/keeptrack](https://github.com/devpro/keeptrack), under the [PolyForm Strict License 1.0.0](https://polyformproject.org/licenses/strict/1.0.0/).

- It may be read, run for personal noncommercial purposes, and contributed to.

- Hosting it for others, or any commercial use, needs the owner's written permission.

---

## In this lab

Step          | What
--------------|---------------------------------------------------------------------------------
Sources       | Clone the branch [[ KEEPTRACK_BRANCH ]], build, run the unit tests
Database      | Start `mongod`, create the indexes
Configuration | Local authentication, with no Firebase project
Run           | Start `WebApi` and `BlazorApp`
Guided tour   | Sign in, follow a TV show, plan a movie, add a game, then see what to watch next
