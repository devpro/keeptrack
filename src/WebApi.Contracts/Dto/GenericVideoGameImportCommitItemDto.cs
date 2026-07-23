using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, carrying whatever the user edited in the review table.
/// </summary>
public class GenericVideoGameImportCommitItemDto
{
    /// <summary>
    /// The <see cref="GenericVideoGameImportPreviewRowDto.RowId"/> this came from. Not used for anything
    /// server-side beyond echoing it back in error messages - the row's data is taken entirely from this
    /// DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the source export listed it, even if <see cref="Title"/> was edited in the
    /// review UI - recorded in the created item's notes, since reference-data linking is expected to
    /// overwrite <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    /// <summary>
    /// Required and validated server-side - the export always carries one, but a user-edited value could be
    /// blanked out by mistake.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>The store's own specific product/edition text - see <see cref="GenericVideoGameImportPreviewRowDto.ProductName"/>.</summary>
    public string? ProductName { get; set; }

    /// <summary>
    /// The storefront's own transaction id and order id - together they're the server-derived owned-copy
    /// <c>Reference</c> (see <c>GenericVideoGameImportService.FormatReference</c> in the Domain project),
    /// which also doubles as the exact dedup key. Both are echoed back from the preview row rather than
    /// accepting a client-supplied <c>Reference</c> string directly, so the format can't drift out of sync
    /// with what a later re-preview checks against.
    /// </summary>
    public required string TransactionId { get; set; }

    public required string OrderId { get; set; }

    public required string Vendor { get; set; }

    /// <summary>
    /// Publication/release year, if the user happens to know it - the export has no source for this, so it's
    /// never auto-filled.
    /// </summary>
    public int? Year { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public CopyType CopyType { get; set; }
}
