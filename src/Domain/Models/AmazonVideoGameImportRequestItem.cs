namespace Keeptrack.Domain.Models;

/// <summary>
/// The video game shape for <see cref="Services.OwnedItemImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/>.
/// <see cref="VideoGameModel"/> has no <see cref="OwnedVersionModel"/>: its copies are <see cref="VideoGamePlatformModel"/> entries, whose required platform name Amazon's export never supplies.
/// See <see cref="AmazonOwnedItemImportRequestItem"/> for the other domains' shape.
/// </summary>
public class AmazonVideoGameImportRequestItem
{
    public required string Title { get; set; }

    public required string AmazonTitle { get; set; }

    public int? Year { get; set; }

    public required VideoGamePlatformModel Platform { get; set; }
}
