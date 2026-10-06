namespace Keeptrack.Domain.Models;

/// <summary>
/// One row the user selected or edited in the video game import review UI, translated from the web contract.
/// It is the input to <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>.
/// </summary>
public class GenericVideoGameImportRequestItem
{
    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the export listed it, before any edit in the review UI.
    /// It is kept in the created item's notes, since reference linking may overwrite <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    public int? Year { get; set; }

    public required VideoGamePlatformModel Platform { get; set; }
}
