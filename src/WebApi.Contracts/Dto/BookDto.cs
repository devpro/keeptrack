using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Book data transfer object.
/// </summary>
public class BookDto : IHasId, IReferenceLinkedDto
{
    /// <summary>
    /// Book ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Book title.
    /// </summary>
    /// <example>The Hobbit</example>
    public string? Title { get; set; }

    /// <summary>
    /// Book author.
    /// </summary>
    /// <example>J.R.R. Tolkien</example>
    public string? Author { get; set; }

    /// <summary>
    /// Book series.
    /// </summary>
    /// <example>Middle-earth Universe</example>
    public string? Series { get; set; }

    /// <summary>
    /// Publication year.
    /// </summary>
    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Genre { get; set; }

    /// <summary>
    /// Book language - free text, auto-filled on link/refresh from providers that report one (BnF does;
    /// Open Library doesn't yet), always freely editable afterward.
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// Edited on the detail page only (never the Add form) - auto-filled from a linked reference's own
    /// ISBN when one is reported, and usable as an optional, precise input when checking for a reference
    /// match against Google Books specifically.
    /// </summary>
    public string? Isbn { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Book finished reading date.
    /// </summary>
    public DateOnly? FirstReadAt { get; set; }

    /// <summary>
    /// Id of the linked <c>book_reference</c> document, when a match has been found.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover image URL shown on the list page - <see cref="CustomImageUrl"/> when set, otherwise the linked
    /// reference document's own cover. Read-only, hydrated server-side on list reads; never accepted from
    /// client input (edit <see cref="CustomImageUrl"/> instead).
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// Tenant-owned cover image override, freely editable - takes priority over the linked reference's
    /// cover wherever one is shown. Null means "use the reference's cover, if any".
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this book - the book counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version. Never populated on a
    /// returned item - see <see cref="VideoGameDto.Platform"/> for the convention.
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches items with no <see cref="FirstReadAt"/> set. Never populated on
    /// a returned item - see <see cref="IsOwned"/> for the convention.
    /// </summary>
    public bool IsUnread { get; set; }

    public bool IsWishlisted { get; set; }
}
