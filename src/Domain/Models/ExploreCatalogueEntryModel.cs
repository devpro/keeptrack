using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One entry of a provider's "best of" ranking, stored locally.
/// <c>ExploreCatalogueRefreshService</c> refreshes it periodically from the discovery provider (TMDB's top-rated lists, IGDB's rating orders), and <c>ExploreService</c> reads it instead of calling the provider on every request.
/// <para>
/// Owner-less like the <c>*_reference</c> collections: a provider's ranking is a public fact, identical for every tenant.
/// Only Explore's exclusion of what the caller already tracks is per user, applied at read time over this shared list.
/// Storing the ranking lets a user page deep into it through an indexed read, rather than re-pulling the provider's first pages on every request.
/// </para>
/// </summary>
public class ExploreCatalogueEntryModel
{
    public string? Id { get; set; }

    /// <summary>Which discovery domain this entry belongs to.</summary>
    public required ExploreItemType ItemType { get; set; }

    /// <summary>
    /// Which ordering produced <see cref="Rank"/>, as a rating source key ("tmdb", "igdb", "igdbcritic").
    /// It is not necessarily the source whose number is displayed.
    /// TMDB has one top-rated ordering whether movies show TMDB or IMDb ratings, so a movie list shown with IMDb ratings is still the "tmdb" ranking, with an extra entry in <see cref="Ratings"/>.
    /// A game provider sorts differently per source, so video games have one stored ranking per source.
    /// </summary>
    public required string Ranking { get; set; }

    /// <summary>The provider's own id, in the discovery provider's number space (a TMDB id, an IGDB id).</summary>
    public required string ExternalId { get; set; }

    /// <summary>
    /// 1-based position in <see cref="Ranking"/>, and the read path's cursor: a page asks for the entries ranked after the last rank it saw.
    /// That keeps deep paging stable although per-user exclusions apply afterwards, where a skip and limit page would drop and duplicate entries as the exclusions shift.
    /// </summary>
    public required int Rank { get; set; }

    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public string? ImageUrl { get; set; }

    /// <summary>
    /// Every rating this entry is known by, keyed by source ("tmdb" and "imdb" for movies and TV, "igdb" and "igdbcritic" for games), so switching the displayed source costs no provider call.
    /// A refresh pass only sets the keys it fetched, leaving the others in place, notably a backfilled "imdb" value that cost an OMDb call.
    /// </summary>
    public Dictionary<string, double> Ratings { get; set; } = [];

    /// <summary>
    /// When a rating source was last attempted for this entry, whether or not it produced a value.
    /// It stops the IMDb backfill spending the shared OMDb budget again on every pass for the titles OMDb has no rating for.
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    /// <summary>
    /// The title's provider pages, per source key ("tmdb", "imdb", "igdb", "rawg").
    /// A suggestion is not in the collection yet, so it has no detail page, and its card opens the provider page instead.
    /// <para>
    /// Stored rather than derived, since IGDB and RAWG key their pages on a slug rather than on <see cref="ExternalId"/>, so the URL comes from the listing that produced the entry.
    /// Every refresh pass writes the discovery provider's URL, and the IMDb backfill writes the "imdb" one from the id it already resolved.
    /// </para>
    /// </summary>
    public Dictionary<string, string> WebUrls { get; set; } = [];

    /// <summary>
    /// The refresh pass that last wrote this entry.
    /// Every entry written by one pass shares its timestamp.
    /// The pass then drops what fell out of the ranking with a single "older than me" delete, and the oldest stamp in a ranking tells the scheduler whether the last pass completed.
    /// </summary>
    public DateTime RefreshedAt { get; set; }
}
