using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Album metadata from Discogs, shared by every tenant.
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class AlbumReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// The album artist's shared <see cref="PersonReferenceModel"/>, deduplicated by the artist's Discogs id like TV and movie cast.
    /// Null when Discogs reported no artist id to deduplicate by.
    /// </summary>
    public string? ArtistReferenceId { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, artist) combination confirmed to mean this album (see <see cref="TvShowReferenceModel.MatchedAliases"/>).
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<ReferenceTrackModel> Tracks { get; set; } = [];

    /// <summary>Aggregate ratings keyed by source ("discogs"), see <see cref="ReferenceRatingModel"/>.</summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
