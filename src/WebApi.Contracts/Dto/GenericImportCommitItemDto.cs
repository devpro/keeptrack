using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, with whatever the user edited in the review table.
/// </summary>
public class GenericImportCommitItemDto
{
    /// <summary>
    /// The <see cref="GenericImportPreviewRowDto.RowId"/> this came from, only echoed back in error messages, since the row's data comes from this DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the file listed it, even if <see cref="Title"/> was edited in the review UI.
    /// It is recorded in the created item's notes, since reference linking may overwrite <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    /// <summary>
    /// Which trackable type to create or merge this row as.
    /// Nullable and required by the server, like <see cref="Platform"/> for a video game, so a row with a blank "Type" is never committed as the wrong type.
    /// </summary>
    public ImportMediaType? MediaType { get; set; }

    public int? Year { get; set; }

    /// <summary>Books only, ignored for every other <see cref="MediaType"/>.</summary>
    public string? Author { get; set; }

    /// <summary>Books only, ignored for every other <see cref="MediaType"/>.</summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// Video games only: required by the server when <see cref="MediaType"/> is <see cref="ImportMediaType.VideoGame"/>, and ignored otherwise.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Item condition ("New", "Used"), kept on the created copy's product name rather than discarded.
    /// </summary>
    public string? Condition { get; set; }

    /// <summary>
    /// The order number and product id, echoed from the preview row, from which the server builds the copy's <c>Reference</c> and exact dedup key (<c>GenericImportService.FormatReference</c>).
    /// Echoed rather than a client-built reference, so the format matches what a later preview checks, and several items of one order stay distinct.
    /// </summary>
    public string? OrderId { get; set; }

    public string? ProductId { get; set; }

    public string? Vendor { get; set; }

    /// <summary>
    /// The "Website" column, echoed from the preview row, which the server puts into the copy's Reference and dedup key, independent of the Vendor.
    /// </summary>
    public string? Website { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public CopyType CopyType { get; set; }
}
