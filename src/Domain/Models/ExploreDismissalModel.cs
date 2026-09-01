namespace Keeptrack.Domain.Models;

/// <summary>
/// One "don't suggest this to me again" record: an owner has dismissed a specific provider title from their
/// Explore list for a given domain. Per-user (owner-scoped). The natural key is
/// (owner, item type, external source, external id) - dismissing the same suggestion twice is idempotent.
/// A dismissal deliberately points at the *provider's* title, not at a local reference document: an Explore
/// suggestion is by definition something nobody tracks yet, so there is usually no reference document to
/// point at until the title is actually added.
/// </summary>
public class ExploreDismissalModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    /// <summary>Which domain the dismissed title belongs to.</summary>
    public required ExploreItemType ItemType { get; set; }

    /// <summary>
    /// Which provider <see cref="ExternalId"/> belongs to ("tmdb" for movies/TV, "rawg" for video games) -
    /// the *discovery* provider the suggestion came from, not the admin-selected rating source (an IMDb-ranked
    /// movie suggestion is still a TMDB id). Stored explicitly rather than inferred from
    /// <see cref="ItemType"/>, so an id can never be read against the wrong provider's number space if a
    /// domain's discovery provider ever changes.
    /// </summary>
    public required string ExternalSource { get; set; }

    /// <summary>The provider's own id of the dismissed title, in <see cref="ExternalSource"/>'s number space.</summary>
    public required string ExternalId { get; set; }
}
