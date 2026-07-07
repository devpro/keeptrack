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
public class TvShowReferenceModel : IHasId
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
    /// Every normalized title string that has ever been confirmed (via TMDB resolution, automatic or
    /// admin-picked) to mean this show - not just <see cref="TitleNormalized"/>. A tenant typing a
    /// different-language title, a typo, or a regional variant that an admin resolved to this same TMDB
    /// entry gets remembered here, so the next tenant with that exact same text matches instantly without
    /// a fresh TMDB search. Always includes <see cref="TitleNormalized"/> itself.
    /// </summary>
    public List<string> MatchedTitles { get; set; } = [];

    public List<ReferenceEpisodeModel> Episodes { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    public string? PosterUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
