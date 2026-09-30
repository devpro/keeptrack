using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One entry of a materialized provider "best of" ranking - the local, shared copy of what a discovery
/// provider (TMDB's top-rated list, RAWG's ordered catalogue) reports, refreshed periodically by
/// <c>ExploreCatalogueRefreshService</c> and read by <c>ExploreService</c> instead of calling the provider on
/// every request.
/// <para>
/// Owner-less on purpose, and for the same reason the <c>*_reference</c> collections are: the provider's
/// ranking is a public fact about real works, identical for every tenant. Only the *exclusion* half of
/// Explore ("does this caller already track it?") is per-user, and that is applied at read time over this
/// shared list. Materializing it is what lifts Explore's old ceiling - the read path pages through a locally
/// stored, indexed ranking instead of re-pulling the provider's first few pages on every single request.
/// </para>
/// </summary>
public class ExploreCatalogueEntryModel
{
    public string? Id { get; set; }

    /// <summary>Which discovery domain this entry belongs to.</summary>
    public required ExploreItemType ItemType { get; set; }

    /// <summary>
    /// Which *ordering* produced <see cref="Rank"/> - a rating source key ("tmdb", "rawg", "metacritic").
    /// Deliberately not the same thing as the source whose number is *displayed*: TMDB has a single
    /// top-rated ordering whether movies are shown with TMDB or IMDb ratings, so an IMDb-ranked movie list is
    /// still ranking "tmdb" with an extra entry in <see cref="Ratings"/>. RAWG genuinely sorts differently per
    /// source, so video games have one stored ranking per source.
    /// </summary>
    public required string Ranking { get; set; }

    /// <summary>The provider's own id, in the discovery provider's number space (a TMDB id, a RAWG id).</summary>
    public required string ExternalId { get; set; }

    /// <summary>
    /// 1-based position in <see cref="Ranking"/>. The read path's cursor: a page asks for the entries ranked
    /// after the last rank it saw, which is what makes deep paging stable even though the per-user exclusions
    /// are applied afterwards (a skip/limit page would drop and duplicate entries as the exclusions shift).
    /// </summary>
    public required int Rank { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? ImageUrl { get; set; }

    /// <summary>
    /// Every rating this entry is known by, keyed by source ("tmdb"/"imdb" for movies and TV, "rawg"/
    /// "metacritic" for games) - so switching the admin's displayed source costs no provider call. A refresh
    /// pass only ever sets the keys it actually fetched, leaving the others (notably a backfilled "imdb"
    /// value, which costs an OMDb call to obtain) in place.
    /// </summary>
    public Dictionary<string, double> Ratings { get; set; } = [];

    /// <summary>
    /// When a rating source was last *attempted* for this entry, whether or not it produced a value - the
    /// marker that stops the bounded IMDb backfill re-spending its whole per-pass budget, every pass, on the
    /// handful of titles OMDb has no rating for.
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    /// <summary>
    /// Where a human can go and read more about this title, per source key ("tmdb"/"imdb", "igdb"/"rawg") - so
    /// a suggestion card can be opened at the provider before it is added or dismissed, which is the one thing
    /// Explore cannot answer itself (a suggestion is by definition not yet in the collection, so it has no
    /// detail page to open).
    /// <para>
    /// Stored rather than derived because two of the four cannot be derived: IGDB and RAWG key their pages on
    /// a slug, which <see cref="ExternalId"/> is not, so the URL has to come back from the listing that
    /// produced the entry. The discovery provider's URL is written by every refresh pass; the "imdb" one is
    /// filled in by the same backfill that fetches the IMDb rating, out of the id it already had to resolve.
    /// </para>
    /// </summary>
    public Dictionary<string, string> WebUrls { get; set; } = [];

    /// <summary>
    /// The refresh pass that last wrote this entry. Every entry written by one pass shares its timestamp, so
    /// the pass can drop what fell out of the ranking with a single "older than me" delete, and the *oldest*
    /// stamp in a ranking tells the scheduler whether the last pass actually completed.
    /// </summary>
    public DateTime RefreshedAt { get; set; }
}
