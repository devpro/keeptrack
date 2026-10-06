using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, carrying whatever the user edited in the review table.
/// </summary>
public class GenericVideoGameImportCommitItemDto
{
    /// <summary>
    /// The <see cref="GenericVideoGameImportPreviewRowDto.RowId"/> this came from, only echoed back in error messages, since the row's data comes from this DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the export listed it, even if <see cref="Title"/> was edited in the review UI.
    /// It is recorded in the created item's notes, since reference linking may overwrite <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    /// <summary>
    /// Required by the server: the export always carries one, but an edit could blank it.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>The store's product or edition text (see <see cref="GenericVideoGameImportPreviewRowDto.ProductName"/>).</summary>
    public string? ProductName { get; set; }

    /// <summary>
    /// The store's transaction id and, with <see cref="OrderId"/>, the source of the copy's <c>Reference</c> and exact dedup key (<c>GenericVideoGameImportService.FormatReference</c>).
    /// Echoed from the preview row rather than a client-built reference, so the format matches what a later preview checks.
    /// </summary>
    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public required string Vendor { get; set; }

    /// <summary>
    /// Release year, if the user knows it, never filled automatically since the export has none.
    /// </summary>
    public int? Year { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public CopyType CopyType { get; set; }
}
