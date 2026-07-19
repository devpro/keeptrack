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
    /// recorded in the created item's notes, since reference-data linking is expected to overwrite
    /// <see cref="Title"/> later.
    /// </summary>
    public required string AmazonTitle { get; set; }

    /// <summary>
    /// Which trackable item type to create/merge this row as. Nullable (and validated as required
    /// server-side, same as <see cref="Platform"/> for a video game) rather than defaulting to
    /// <see cref="AmazonImportMediaType.Book"/>, so a row the "looks like a book" heuristic didn't suggest
    /// can't be silently committed as a book just because the reviewer forgot to pick a type.
    /// </summary>
    public AmazonImportMediaType? MediaType { get; set; }

    /// <summary>
    /// Publication/release year, if the user happens to know it - Amazon's export has no source for this
    /// (order date is the purchase year, not the item's), so it's never auto-filled.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>Book-only - ignored for every other <see cref="MediaType"/>.</summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// VideoGame-only (PS5/Xbox/PC/Switch...) - required and validated server-side when
    /// <see cref="MediaType"/> is <see cref="AmazonImportMediaType.VideoGame"/>, ignored otherwise.
    /// Amazon's export has no signal for this at all.
    /// </summary>
    public string? Platform { get; set; }

    public DateOnly? AcquiredAt { get; set; }

    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    public string? Reference { get; set; }

    public CopyType CopyType { get; set; }
}
