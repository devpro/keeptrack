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
    /// Book language, free text, filled on link and refresh when the provider reports one (BnF does, Open Library does not), and editable afterward.
    /// </summary>
    public string? Language { get; set; }

    /// <summary>
    /// Edited on the detail page only, filled from the linked reference's ISBN when the provider reports one.
    /// When set, "check for reference match" searches by ISBN first.
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
    /// The cover shown on the list page: <see cref="CustomImageUrl"/> when set, else the linked reference's cover.
    /// Read-only, hydrated server side on list reads and never accepted from the client, which edits <see cref="CustomImageUrl"/> instead.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// The linked reference's rating from the linking book provider (0 to 5), on <see cref="ReferenceRatingScale"/>.
    /// Managed by the server on link and refresh, round-tripped on edits, and null until linked.
    /// The full breakdown is <see cref="BookReferenceDto.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for every book provider), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> came from ("tmdb", "imdb", "igdb"), so the value is labelled rather than a bare number.
    /// Managed by the server on link and refresh, and round-tripped on edits.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    /// <summary>
    /// The tenant's own cover, freely editable, which takes priority over the linked reference's cover wherever one is shown.
    /// Null means the reference's cover, if any.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this book, which counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version.
    /// Never set on a returned item (see <see cref="VideoGameDto.Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches items with no <see cref="FirstReadAt"/> set.
    /// Never set on a returned item (see <see cref="IsOwned"/>).
    /// </summary>
    public bool IsUnread { get; set; }

    public bool IsWishlisted { get; set; }
}
