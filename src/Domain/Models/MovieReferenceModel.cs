using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic movie metadata sourced from an external provider such as TMDB.
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class MovieReferenceModel : IHasId
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination that has ever been confirmed (via TMDB resolution, automatic or
    /// admin-picked) to mean this movie - not just <see cref="TitleNormalized"/>/<see cref="Year"/>. See
    /// <see cref="TvShowReferenceModel.MatchedAliases"/> for the full rationale.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    /// <summary>
    /// Aggregate ratings for this movie keyed by source ("tmdb" today; "imdb"/others later) - see
    /// <see cref="ReferenceRatingModel"/>. Canonical here on the shared reference document; the primary
    /// source's value is denormalized onto each tenant's <see cref="MovieModel.ReferenceRating"/> on link.
    /// </summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    /// <summary>
    /// When each rating source was last *attempted* for this movie, whether or not it produced a value -
    /// see <see cref="TvShowReferenceModel.RatingsCheckedAt"/> for what it protects against.
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
