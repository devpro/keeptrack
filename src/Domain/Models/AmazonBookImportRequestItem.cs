namespace Keeptrack.Domain.Models;

/// <summary>
/// One user-selected/edited row from the review UI, already translated from the web contract - the input
/// to <see cref="Services.AmazonBookImportMergeService.ComputeCommitPlan"/>.
/// </summary>
public class AmazonBookImportRequestItem
{
    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as Amazon listed it (before any edit the user made in the review UI) - preserved
    /// in <see cref="Services.AmazonBookImportMergeService.ComputeCommitPlan"/>'s notes for a newly-created
    /// book, since reference-data linking is expected to overwrite <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    public int? Year { get; set; }

    public string? Isbn { get; set; }

    public required OwnedVersionModel OwnedVersion { get; set; }
}
