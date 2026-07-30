namespace Keeptrack.Domain.Models;

/// <summary>
/// One "don't suggest this to me again" record: an owner has dismissed a specific provider title (by its
/// external id - a TMDB id today) from their Explore list for a given domain. Per-user (owner-scoped). The
/// natural key is (owner, type, external id) - dismissing the same suggestion twice is idempotent.
/// </summary>
public class ExploreDismissalModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required ExploreItemType ReferenceType { get; set; }

    /// <summary>The provider's external id (TMDB id) of the dismissed title.</summary>
    public required string ExternalId { get; set; }
}
