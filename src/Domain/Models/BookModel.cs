using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class BookModel : IHasIdAndOwnerId, IReferenceLinkedModel
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
    /// Denormalized copy of the linked reference's primary-source (the linking book provider's, 0-5)
    /// rating, on <see cref="ReferenceRatingScale"/>. Copied down on link/refresh for fast list display
    /// and sorting; the authoritative data is on <see cref="BookReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for the current book providers); null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// Which rating source <see cref="ReferenceRating"/> was taken from ("tmdb", "imdb", "rawg", ...) - see
    /// <c>RatingSourceCatalog</c>. Stamped on every link/refresh, and stamped even when that source has no
    /// value for this reference: it records which source the denormalized copy was computed from, not where a
    /// number came from, which is what lets the admin "recompute" action tell an item that is already on the
    /// selected source from one that still needs re-stamping. Null only for items linked before this existed.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

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
