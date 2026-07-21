namespace Keeptrack.Domain.Models;

/// <summary>
/// One user-selected/edited row from the generic video game import review UI, already translated from the
/// web contract - the input to <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>.
/// </summary>
public class GenericVideoGameImportRequestItem
{
    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the source export listed it (before any edit the user made in the review UI) -
    /// preserved in the created item's notes, since reference-data linking is expected to overwrite
    /// <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    public int? Year { get; set; }

    public required VideoGamePlatformModel Platform { get; set; }
}
