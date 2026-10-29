# Guided tour

The Run button of each block below drives the [lab browser](:panel:vnc), while the block waits for the result in MongoDB.
Every action can be done by hand as well: the browser is a real Chrome.

## Sign in

The login page shows a form instead of the GitHub and Google buttons.
Any email is accepted, and the role picks the tier:

Role         | Sees
-------------|--------------------------------------------------------------
Free preview | Movies and TV shows, up to `Features:FreeTierItemLimit` items
Member       | Every collection and journal, the imports
Admin        | The reference data pages too

The tour signs in as a member, with this email:

```text
[[ DEMO_EMAIL ]]
```

<!-- verify: interactive action=tour.sign-in capture="signs in as (\S+@\S+)" timeout=60 -->

```bash exec
echo "The lab browser signs in as $DEMO_EMAIL on ${BLAZORAPP_URL}/account/login" ; \
sleep 5 ; echo "Ready for the next block"
```

The block waits a few seconds, the time the home page takes to open its SignalR circuit.
Blazor Server sends a prerendered page first, and a button clicked before the circuit is up does nothing, which is why the end-to-end tests retry their first click.

[The browser](:panel:vnc) is on the home page, and the sidebar lists every collection.

## Movies, TV shows, video games

These three are what Keeptrack is mostly used for: one place for everything watched and played, where TV Time and a game backlog used to be two.
Each is added the same way, with a title and a year, and on save `WebApi` looks the title up at its provider:

Type       | Provider | With a key
-----------|----------|-----------------------------------------------------------
Movie      | TMDB     | Poster, synopsis, cast, TMDB rating, IMDb rating with OMDb
TV show    | TMDB     | Seasons and episodes to tick, which **Watch next** follows
Video game | IGDB     | Cover, platforms, genres, rating

Without a key, the item is saved as typed and stays unlinked, and the rest works the same.

1. Add a movie:

   <!-- verify: interactive action=tour.add-movie capture="Waiting for (?<title>.+) \((?<year>\d{4})\)" timeout=120 expect="Found The Matrix" -->

   ```bash exec
   mongosh --quiet mongodb://localhost:27017/keeptrack_dev --eval '
   const [collection, title, year] = ["movie", "The Matrix", 1999];
   print(`Waiting for ${title} (${year}) in the ${collection} collection`);
   for (let i = 0; i < 60; i++) {
     const d = db.getCollection(collection).findOne({ title });
     if (d) { print(`Found ${d.title} (${d.year}), owner_id ${d.owner_id}, reference_id ${d.reference_id ?? "none"}`); quit(0); }
     sleep(2000);
   }
   quit(1);'
   ```

   `owner_id` is the email: in local mode, the `sub` claim of the token is the normalized email, so signing in again with it reaches the same items.
   In Firebase mode it is the Firebase user id, which is why a database does not move from one mode to the other as it is.

2. Add a TV show:

   <!-- verify: interactive action=tour.add-tv-show capture="Waiting for (?<title>.+) \((?<year>\d{4})\)" timeout=120 expect="Found Severance" -->

   ```bash exec
   mongosh --quiet mongodb://localhost:27017/keeptrack_dev --eval '
   const [collection, title, year] = ["tvshow", "Severance", 2022];
   print(`Waiting for ${title} (${year}) in the ${collection} collection`);
   for (let i = 0; i < 60; i++) {
     const d = db.getCollection(collection).findOne({ title });
     if (d) { print(`Found ${d.title} (${d.year}), owner_id ${d.owner_id}, reference_id ${d.reference_id ?? "none"}`); quit(0); }
     sleep(2000);
   }
   quit(1);'
   ```

3. Add a video game:

   <!-- verify: interactive action=tour.add-video-game capture="Waiting for (?<title>.+) \((?<year>\d{4})\)" timeout=120 expect="Found Hades" -->

   ```bash exec
   mongosh --quiet mongodb://localhost:27017/keeptrack_dev --eval '
   const [collection, title, year] = ["videogame", "Hades", 2020];
   print(`Waiting for ${title} (${year}) in the ${collection} collection`);
   for (let i = 0; i < 60; i++) {
     const d = db.getCollection(collection).findOne({ title });
     if (d) { print(`Found ${d.title} (${d.year}), owner_id ${d.owner_id}, reference_id ${d.reference_id ?? "none"}`); quit(0); }
     sleep(2000);
   }
   quit(1);'
   ```

4. [✓ Check the movie is listed](:action:tour.movie-listed), from the list page this time.

## Explore

Everything else is a click away in the sidebar:

- **Watch next**, the next episode of each show in progress.
- **Explore**, the top-rated titles not tracked yet, from the providers given a key.
- **Import**, a TV Time export among others, to bring the shows and movies already watched.
- **Wishlist**, with a link to share it anonymously.
- **Quick add**, one form for every type.
- **Manage account**, under the email at the top, to share whole collections with other accounts.

> [!TIP]
> Signing out and in again with another email is another account, with its own empty collections.
> An admin sees **Admin** in the sidebar, for the reference data shared by every account.
