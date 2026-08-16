using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class AlbumModel : IHasIdAndOwnerId, IReferenceLinkedModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    public required string Artist { get; set; }

    public int? Year { get; set; }

    public string? Genre { get; set; }

    public float? Rating { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Denormalized copy of the linked reference's primary-source (Discogs, 0-5) rating, on
    /// <see cref="ReferenceRatingScale"/>. Copied down on link/refresh for fast list display and sorting;
    /// the authoritative data is on <see cref="AlbumReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for Discogs); null when there is no reference rating.</summary>
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
}
