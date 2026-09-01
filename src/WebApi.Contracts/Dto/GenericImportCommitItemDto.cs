using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One row selected for import, carrying whatever the user reviewed/edited in the review table.
/// </summary>
public class GenericImportCommitItemDto
{
    /// <summary>
    /// The <see cref="GenericImportPreviewRowDto.RowId"/> this came from. Not used server-side beyond echoing
    /// it back in error messages - the row's data is taken entirely from this DTO's own fields.
    /// </summary>
    public required string RowId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// The title exactly as the source file listed it, even if <see cref="Title"/> was edited in the review UI
    /// - recorded in the created item's notes, since reference-data linking is expected to overwrite
    /// <see cref="Title"/> later.
    /// </summary>
    public required string SourceTitle { get; set; }

    /// <summary>
    /// Which trackable item type to create/merge this row as. Nullable and validated as required server-side
    /// (same as <see cref="Platform"/> for a video game) so a row whose "Type" column was blank can't be
    /// silently committed as the wrong type - the reviewer must pick one.
    /// </summary>
    public ImportMediaType? MediaType { get; set; }

    public int? Year { get; set; }

    /// <summary>Book-only - ignored for every other <see cref="MediaType"/>.</summary>
    public string? Author { get; set; }

    /// <summary>Book-only - ignored for every other <see cref="MediaType"/>.</summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// VideoGame-only - required and validated server-side when <see cref="MediaType"/> is
    /// <see cref="ImportMediaType.VideoGame"/>, ignored otherwise.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Item condition ("New", "Used"...) - persisted onto the created owned copy's Product field rather than
    /// discarded, so the retailer's condition is not lost on import.
    /// </summary>
    public string? Condition { get; set; }

    /// <summary>
    /// The order number and product id, echoed back from the preview row - together with the vendor they're the
    /// server-derived owned-copy <c>Reference</c> (see <c>GenericImportService.FormatReference</c>), which also
    /// doubles as the exact dedup key. Echoed rather than accepting a client-supplied <c>Reference</c> so the
    /// format can't drift from what a later re-preview checks against, and so a single order's several line
    /// items stay distinct from one another.
    /// </summary>
    public string? OrderId { get; set; }

    public string? ProductId { get; set; }

    public string? Vendor { get; set; }

    /// <summary>
    /// The "Website" column value, echoed back from the preview row - the server puts it into the owned copy's
    /// Reference (and dedup key) via <c>GenericImportService.FormatReference</c>, independent of the Vendor field.
    /// </summary>
    public string? Website { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public CopyType CopyType { get; set; }
}
