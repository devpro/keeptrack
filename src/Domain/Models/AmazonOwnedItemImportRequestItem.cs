namespace Keeptrack.Domain.Models;

/// <summary>
/// One row the user selected or edited in the review UI, translated from the web contract.
/// It is the input to <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>
/// for the domains using <see cref="OwnedVersionModel"/> (Book, Movie, TvShow, Gear, Collectible).
/// See <see cref="AmazonVideoGameImportRequestItem"/> for VideoGame's own shape.
/// </summary>
public class AmazonOwnedItemImportRequestItem
{
    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as Amazon listed it, before any edit in the review UI.
    /// It is kept in the created item's notes, since reference linking may overwrite <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    public int? Year { get; set; }

    /// <summary>Books only, see <see cref="Services.AmazonImportMergeService.BuildAmazonProvenanceNotes"/>.</summary>
    public string? Isbn { get; set; }

    public required OwnedVersionModel OwnedVersion { get; set; }
}
