using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, carrying whatever the user edited in the review table.
/// </summary>
public class AmazonImportCommitItemDto
{
    /// <summary>
    /// The <see cref="AmazonOrderPreviewRowDto.RowId"/> this came from, only echoed back in error messages, since the row's data comes from this DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    /// <summary>
    /// The order number and, with <see cref="Asin"/>, Amazon's product id: the server builds the owned copy's <c>Reference</c> and exact dedup key from them (<c>AmazonImportMergeService.FormatOrderReference</c>).
    /// They are echoed from the preview row rather than a client-built reference, so the format matches what a later preview checks, and several items of one order stay distinct.
    /// </summary>
    public required string OrderId { get; set; }

    public required string Asin { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as Amazon listed it, even if <see cref="Title"/> was edited in the review UI.
    /// It is recorded in the created item's notes, since reference linking may overwrite <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    /// <summary>
    /// Which trackable type to create or merge this row as.
    /// Nullable and required by the server, like <see cref="Platform"/> for a video game, rather than defaulting to <see cref="AmazonImportMediaType.Book"/>, so a row is never committed as a book because the reviewer forgot to pick a type.
    /// </summary>
    public AmazonImportMediaType? MediaType { get; set; }

    /// <summary>
    /// Publication or release year, if the user knows it.
    /// Never filled automatically, since the export's order date is the purchase year, not the item's.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>Books only, ignored for every other <see cref="MediaType"/>.</summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// Video games only (PS5, Xbox, PC, Switch): required by the server when <see cref="MediaType"/> is <see cref="AmazonImportMediaType.VideoGame"/>, and ignored otherwise.
    /// Amazon's export carries no platform.
    /// </summary>
    public string? Platform { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    public CopyType CopyType { get; set; }
}
