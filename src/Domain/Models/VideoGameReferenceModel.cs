using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Video game metadata from a game provider (IGDB, RAWG), shared by every tenant.
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
    /// Every platform the provider lists the game as released on, distinct from the tenant's own <see cref="VideoGameModel.Platforms"/>, which reference data never overwrites.
    /// </summary>
    public List<string> Platforms { get; set; } = [];

    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination confirmed to mean this game (see <see cref="TvShowReferenceModel.MatchedAliases"/>).
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    /// <summary>
    /// Aggregate ratings keyed by source: "igdb" and "igdbcritic" (0 to 100), and "rawg" (0 to 5) and "metacritic" (0 to 100) on RAWG-linked games, see <see cref="ReferenceRatingModel"/>.
    /// </summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    public string? ImageUrl { get; set; }

    /// <summary>
    /// When this document last had a provider id looked up, keyed by provider, whether or not one was found (see <c>ReferenceEnrichmentService.TryAdoptDefaultVideoGameProviderAsync</c>).
    /// <para>
    /// Like <see cref="TvShowReferenceModel.RatingsCheckedAt"/>, it stops every pass paying the same two calls again for a reference the provider has no unambiguous match for.
    /// It also lets the admin reconciliation queue show what was tried, not only what is missing.
    /// An admin acting on that queue ignores the window, since someone is waiting on the answer.
    /// </para>
    /// </summary>
    public Dictionary<string, DateTime> ProviderAdoptionCheckedAt { get; set; } = [];

    public DateTime? LastEnrichedAt { get; set; }
}
