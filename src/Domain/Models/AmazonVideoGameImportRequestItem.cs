namespace Keeptrack.Domain.Models;

/// <summary>
/// VideoGame's own shape for <see cref="Services.AmazonImportMergeService.ComputeCommitPlan{TModel,TRequestItem}"/> -
/// <see cref="VideoGameModel"/> has no <see cref="OwnedVersionModel"/> concept, using
/// <see cref="VideoGamePlatformModel"/> (with a required platform name Amazon's export can never supply)
/// instead. See <see cref="AmazonOwnedItemImportRequestItem"/> for Book/Movie/TvShow's shared shape.
/// </summary>
public class AmazonVideoGameImportRequestItem
{
    public required string Title { get; set; }

    public required string AmazonTitle { get; set; }

    public int? Year { get; set; }

    public required VideoGamePlatformModel Platform { get; set; }
}
