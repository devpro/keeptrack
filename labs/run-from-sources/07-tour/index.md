# Guided tour

Keeptrack is one place for everything watched and played, where TV Time and a game backlog used to be two.
Each link below acts in the browser, and every step can be done by hand as well.

## Sign in

The login page shows a form instead of the GitHub and Google buttons.
Any email is accepted, and the role picks the tier:

Role         | Sees
-------------|--------------------------------------------------------------
Free preview | Movies and TV shows, up to `Features:FreeTierItemLimit` items
Member       | Every collection and journal, the imports
Admin        | The reference data pages too

[▶ Sign in as a member](:action:tour.sign-in), with this email:

```text
[[ DEMO_EMAIL ]]
```

The sidebar lists every collection.

## A movie to watch

[▶ Add The Matrix (1999)](:action:tour.add-movie) from **Movies**, and put it on the watchlist.

Only a title and a year are typed.
On save, Keeptrack finds the movie at TMDB and links it to its reference: the page opens with the poster, the synopsis, the cast and the ratings.

## A TV show in progress

1. [▶ Add Severance (2022)](:action:tour.add-tv-show) from **TV shows**.
   Linked the same way, its page lists every season and episode.

2. [▶ Mark it current, and tick its first episode as seen](:action:tour.watch-first-episode), in season 1.
   Each episode is ticked the same way, one by one or a whole season at once.

## A game, with a typo

1. [▶ Add Hollow Knight, typed 2007 instead of 2017](:action:tour.add-video-game), from **Video games**.
   No game of that name came out in 2007, so the item is saved as typed, with no cover: Keeptrack never links a reference it is not sure of.

2. [▶ Correct the year, and check for a match](:action:tour.fix-video-game-year).
   With the right year, there is exactly one Hollow Knight: the page shows **Linked!**, then its cover, ratings, genres and platforms.

## What to watch next

1. [▶ Open Watch next](:action:tour.watch-next): Severance waits there with its next episode, season 1 episode 2.

2. [▶ Switch to its Movies tab](:action:tour.watch-next-movies): The Matrix, from the watchlist.

## Explore

The rest is a click away in the sidebar:

- [Explore](:navigate:app:http://localhost:5207/explore), the top-rated titles not tracked yet.
- [Import](:navigate:app:http://localhost:5207/import), a TV Time export among others, to bring everything already watched.
- [Wishlist](:navigate:app:http://localhost:5207/wishlist), with a link to share it.
- [Quick add](:navigate:app:http://localhost:5207/add), one form for every type.
- [Manage account](:navigate:app:http://localhost:5207/account/manage), to share whole collections with other accounts.
