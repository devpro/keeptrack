using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Show metadata from TMDB (title, synopsis, episode guide), shared by every tenant.
/// It has no <c>OwnerId</c>: it holds no user content, only public facts about a real show.
/// Stored once, it is pointed at by every tenant's <see cref="TvShowModel.ReferenceId"/> rather than copied per user.
/// </summary>
public class TvShowReferenceModel : IHasExternalIds
{
    public string? Id { get; set; }

    public required string Title { get; set; }

    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    /// <summary>
    /// Provider name ("tmdb", "imdb") to that provider's id for this show.
    /// A dictionary keeps the document independent of providers: another provider is another entry, not a schema change.
    /// </summary>
    public required Dictionary<string, string> ExternalIds { get; set; }

    /// <summary>
    /// Every (title, year) combination confirmed to mean this show, by automatic resolution or an admin's pick, beyond <see cref="TitleNormalized"/> and <see cref="Year"/>.
    /// A title in another language, a typo or a regional variant resolved to this show is remembered, so the next tenant typing it matches with no provider search.
    /// The year travels with its title variant rather than being one value on the document.
    /// Two tenants, or a tenant and TMDB, can disagree on a show's year, and a single year would reject the tenant whose year differs.
    /// Always includes <see cref="TitleNormalized"/> paired with <see cref="Year"/>.
    /// </summary>
    public List<ReferenceMatchModel> MatchedAliases { get; set; } = [];

    public List<ReferenceEpisodeModel> Episodes { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMemberModel> Cast { get; set; } = [];

    /// <summary>Aggregate ratings keyed by source ("tmdb", "imdb"), see <see cref="ReferenceRatingModel"/>.</summary>
    public Dictionary<string, ReferenceRatingModel> Ratings { get; set; } = [];

    /// <summary>
    /// When each rating source was last attempted for this show, whether or not it produced a value.
    /// It stops the sync's IMDb backfill asking OMDb again on every pass about titles IMDb has nothing for.
    /// Only a source that answered is stamped.
    /// A call that never happened (no key, spent budget, failed request) leaves no trace, so one exhausted afternoon does not write those titles off for the whole window.
    /// Same shape and window as <see cref="ExploreCatalogueEntryModel.RatingsCheckedAt"/>.
    /// </summary>
    public Dictionary<string, DateTime> RatingsCheckedAt { get; set; } = [];

    public string? ImageUrl { get; set; }

    public DateTime? LastEnrichedAt { get; set; }
}
