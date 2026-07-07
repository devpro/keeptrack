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
    /// Every normalized title string that has ever been confirmed (via TMDB resolution, automatic or
    /// admin-picked) to mean this movie - not just <see cref="TitleNormalized"/>. See
    /// <see cref="TvShowReferenceModel.MatchedTitles"/> for the full rationale.
    /// </summary>
    public List<string> MatchedTitles { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    public string? PosterUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
