namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of committing a selected set of Amazon order rows as books.
/// </summary>
public class AmazonImportCommitResultDto
{
    /// <summary>
    /// Brand new books created.
    /// </summary>
    public int BooksCreated { get; set; }

    /// <summary>
    /// Existing books (including ones created earlier in this same commit) that received an additional owned version.
    /// </summary>
    public int BooksMergedInto { get; set; }

    /// <summary>
    /// Total owned versions added across both created and merged-into books.
    /// </summary>
    public int OwnedVersionsAdded { get; set; }
}
