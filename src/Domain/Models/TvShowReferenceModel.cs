using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Shared, tenant-agnostic show metadata (title, synopsis, episode list) sourced from an external
/// provider such as TMDB. Deliberately has no <c>OwnerId</c> - unlike every other collection in
/// Keeptrack, this one carries no user content, only public facts about a real show, so storing it
/// once and pointing every tenant's own <see cref="TvShowModel.ReferenceId"/> at it avoids duplicating
/// the same show's data per user.
/// </summary>
public class TvShowReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// Provider name (e.g. "tmdb") to that provider's id for this show. Keeps the document itself
    /// source-agnostic: adding a second provider later is just another dictionary entry, not a schema change.
    /// </summary>
    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination that has ever been confirmed (via TMDB resolution, automatic or
    /// admin-picked) to mean this show - not just <see cref="TitleNormalized"/>/<see cref="Year"/>. A tenant
    /// typing a different-language title, a typo, or a regional variant that an admin resolved to this same
    /// TMDB entry gets remembered here, so the next tenant with that exact same (title, year) matches
    /// instantly without a fresh TMDB search. Year travels with its specific title variant rather than living
    /// as a single scalar on this document, because two tenants (or a tenant and TMDB's own canonical value)
    /// can legitimately disagree on the year for the same real show - a single top-level year would reject a
    /// tenant whose recorded year genuinely differs from whichever one happens to be canonical. Always
    /// includes <see cref="TitleNormalized"/> paired with <see cref="Year"/>.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<ReferenceEpisodeModel> Episodes { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    /// <summary>Aggregate ratings keyed by source ("tmdb") - see <see cref="ReferenceRatingModel"/>.</summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    /// <summary>
    /// When each rating source was last *attempted* for this show, whether or not it produced a value - the
    /// marker that stops the periodic sync's IMDb backfill re-asking OMDb about the same handful of titles
    /// IMDb genuinely has nothing for, every pass, forever. Only a source that actually answered is stamped;
    /// a call that never happened (no key, spent budget, failed request) deliberately leaves no trace, so one
    /// exhausted afternoon can't write those titles off for the whole re-attempt window. Same shape and same
    /// window as <see cref="ExploreCatalogueEntryModel.RatingsCheckedAt"/>.
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
