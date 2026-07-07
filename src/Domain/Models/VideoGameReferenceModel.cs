using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic video game metadata sourced from an external provider (RAWG).
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class VideoGameReferenceModel : IHasId
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// Every platform RAWG lists as a release target for this game - read-only reference info, distinct
    /// from <see cref="VideoGameModel.Platform"/>, which is the tenant's own "played on" free-text field
    /// and is never overwritten by reference data.
    /// </summary>
    public List<string> Platforms { get; set; } = [];

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination that has ever been confirmed to mean this game - see
    /// <see cref="TvShowReferenceModel.MatchedAliases"/> for the full rationale.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
