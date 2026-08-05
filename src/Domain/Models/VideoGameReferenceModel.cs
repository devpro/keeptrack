using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic video game metadata sourced from an external provider (RAWG).
/// See <see cref="TvShowReferenceModel"/> for why this deliberately has no <c>OwnerId</c>.
/// </summary>
public class VideoGameReferenceModel : IHasExternalIds
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

    /// <summary>
    /// Aggregate ratings keyed by source: "rawg" (0-5 user score, the primary) and "metacritic" (0-100
    /// critic score) when present - see <see cref="ReferenceRatingModel"/>.
    /// </summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    public string? ImageUrl { get; set; }

    /// <summary>
    /// When this document last had a provider id looked up for it, keyed by provider - written whether or not
    /// one was found (see <c>ReferenceEnrichmentService.TryAdoptDefaultVideoGameProviderAsync</c>).
    /// <para>
    /// It exists for the same reason <see cref="TvShowReferenceModel.RatingsCheckedAt"/> does: a reference
    /// whose title the provider genuinely has no unambiguous match for can never be adopted by searching
    /// again, so without a record of the attempt every pass re-pays for the same two calls, forever, for
    /// every such document. It is also what lets the admin reconciliation queue show what has been tried
    /// rather than only what is missing. An admin acting on that queue ignores the window - someone is
    /// waiting on the answer - exactly like the interactive rating paths do.
    /// </para>
    /// </summary>
    public Dictionary<string, DateTime> ProviderAdoptionCheckedAt { get; set; } = [];

    public DateTime? LastEnrichedAt { get; set; }
}
