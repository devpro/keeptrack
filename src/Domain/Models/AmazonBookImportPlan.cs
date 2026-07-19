using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

/// <summary>
/// What <see cref="Services.AmazonBookImportMergeService.ComputeCommitPlan"/> decided: brand new books to
/// create, and existing (or already-created-this-batch) books to update - each already carrying the extra
/// <see cref="OwnedVersionModel"/> appended to its <see cref="BookModel.OwnedVersions"/>.
/// </summary>
public class AmazonBookImportPlan
{
    public List<BookModel> BooksToCreate { get; set; } = [];

    public List<BookModel> BooksToUpdate { get; set; } = [];

    public int OwnedVersionsAdded { get; set; }
}
