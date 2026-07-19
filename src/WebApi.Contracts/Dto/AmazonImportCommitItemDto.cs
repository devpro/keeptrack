using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, carrying whatever the user edited in the review table.
/// </summary>
public class AmazonImportCommitItemDto
{
    /// <summary>
    /// The <see cref="AmazonOrderPreviewRowDto.RowId"/> this came from. Not used for anything server-side
    /// beyond echoing it back in error messages - the row's data is taken entirely from this DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as Amazon listed it, even if <see cref="Title"/> was edited in the review UI -
    /// recorded in the created book's notes, since reference-data linking is expected to overwrite
    /// <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    /// <summary>
    /// Publication year, if the user happens to know it - Amazon's export has no source for this (order
    /// date is the purchase year, not the book's), so it's never auto-filled.
    /// </summary>
    public int? Year { get; set; }

    public string? Isbn { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    public string? Reference { get; set; }

    public CopyType CopyType { get; set; }
}
