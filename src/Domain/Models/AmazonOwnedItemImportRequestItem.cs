namespace Keeptrack.Domain.Models;

/// <summary>
/// One user-selected/edited row from the review UI, already translated from the web contract - the input
/// to <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> for the domains
/// that use <see cref="OwnedVersionModel"/> (Book, Movie, TvShow, Gear, Collectible). See
/// <see cref="AmazonVideoGameImportRequestItem"/> for VideoGame's own shape.
/// </summary>
public class AmazonOwnedItemImportRequestItem
{
    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as Amazon listed it (before any edit the user made in the review UI) - preserved
    /// in the created item's notes, since reference-data linking is expected to overwrite
    /// <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    public int? Year { get; set; }

    /// <summary>Book-only (null for Movie/TvShow/Gear/Collectible) - see <see cref="Services.AmazonImportMergeService.BuildAmazonProvenanceNotes"/>.</summary>
    public string? Isbn { get; set; }

    public required OwnedVersionModel OwnedVersion { get; set; }
}
