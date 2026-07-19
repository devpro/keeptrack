namespace Keeptrack.Domain.Models;

/// <summary>
/// One user-selected/edited row from the review UI, already translated from the web contract - the input
/// to <see cref="Services.AmazonBookImportMergeService.ComputeCommitPlan"/>.
/// </summary>
public class AmazonBookImportRequestItem
{
    public required string Title { get; set; }

    public int? Year { get; set; }

    public string? Isbn { get; set; }

    public required OwnedVersionModel OwnedVersion { get; set; }
}
