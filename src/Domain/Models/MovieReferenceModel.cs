using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Movie metadata from TMDB, shared by every tenant.
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class MovieReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination confirmed to mean this movie, beyond <see cref="TitleNormalized"/> and <see cref="Year"/> (see <see cref="TvShowReferenceModel.MatchedAliases"/>).
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    /// <summary>
    /// Aggregate ratings keyed by source ("tmdb", "imdb"), see <see cref="ReferenceRatingModel"/>.
    /// The primary source's value is copied onto each tenant's <see cref="MovieModel.ReferenceRating"/>.
    /// </summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    /// <summary>
    /// When each rating source was last attempted for this movie, whether or not it produced a value (see <see cref="TvShowReferenceModel.RatingsCheckedAt"/>).
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
