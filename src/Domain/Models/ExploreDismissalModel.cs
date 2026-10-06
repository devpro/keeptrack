namespace Keeptrack.Domain.Models;

/// <summary>
/// A "do not suggest this again" record: an owner dismissed one provider title from their Explore list.
/// The natural key is (owner, item type, external source, external id), so dismissing twice is idempotent.
/// It points at the provider's title rather than a reference document, since a suggestion is something nobody tracks yet and usually has no reference document.
/// </summary>
public class ExploreDismissalModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    /// <summary>Which domain the dismissed title belongs to.</summary>
    public required ExploreItemType ItemType { get; set; }

    /// <summary>
    /// Which provider <see cref="ExternalId"/> belongs to: the discovery provider the suggestion came from ("tmdb", "igdb"), not the selected rating source.
    /// A movie shown with its IMDb rating is still a TMDB id.
    /// It is stored rather than inferred from <see cref="ItemType"/>, so an id is never read in the wrong provider's number space after a domain changes provider.
    /// </summary>
    public required string ExternalSource { get; set; }

    /// <summary>The provider's own id of the dismissed title, in <see cref="ExternalSource"/>'s number space.</summary>
    public required string ExternalId { get; set; }
}
