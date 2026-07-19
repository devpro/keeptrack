using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class BookModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Author { get; set; }

    public string? Series { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Genre { get; set; }

    public string? Language { get; set; }

    /// <summary>
    /// Free text, edited on the detail page only (never the Add form) - auto-filled from a linked
    /// reference's own ISBN when one is reported, and usable as an optional, precise search input when
    /// checking for a reference match (see <see cref="Isbn"/> on <c>BookDetails</c>/the search flow).
    /// </summary>
    public string? Isbn { get; set; }

    public string? Notes { get; set; }

    public DateOnly? FirstReadAt { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Tenant-owned cover image override - takes priority over the linked reference's own cover wherever
    /// a cover is shown (list thumbnail, detail page). Null means "use the reference's cover, if any" -
    /// the previous, only behavior.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only: matches if <see cref="OwnedVersions"/> is non-empty. Never persisted - see
    /// <see cref="MovieModel.IsOwned"/>.
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only: matches if <see cref="FirstReadAt"/> is unset. Never persisted - see
    /// <see cref="IsOwned"/> for the filter-probe convention.
    /// </summary>
    public bool IsUnread { get; set; }

    public bool IsWishlisted { get; set; }
}
