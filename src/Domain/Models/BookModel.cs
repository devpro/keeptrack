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
    /// Free text, edited on the detail page only.
    /// It is filled from the linked reference's ISBN when the provider reports one, and makes "check for reference match" search by ISBN first.
    /// </summary>
    public string? Isbn { get; set; }

    public string? Notes { get; set; }

    public DateOnly? FirstReadAt { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// The linked reference's rating from the linking book provider (0 to 5), on <see cref="ReferenceRatingScale"/>.
    /// Copied on link and refresh so a list displays and sorts without a join.
    /// The authoritative data is <see cref="BookReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for every book provider), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> was taken from, a <c>RatingSourceCatalog</c> key ("tmdb", "imdb", "igdb").
    /// Stamped on every link and refresh, even when that source has no value for this reference.
    /// It records which source the copy was computed from, which is how the admin recompute tells an item already on the selected source from one needing a new stamp.
    /// Null on an item never stamped, which the recompute counts as different.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    /// <summary>
    /// The tenant's own cover, which takes priority over the linked reference's cover wherever a cover is shown (list thumbnail, detail page).
    /// Null means the reference's cover, if any.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter only: matches when <see cref="OwnedVersions"/> is non-empty.
    /// Never persisted (see <see cref="MovieModel.IsOwned"/>).
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter only: matches when <see cref="FirstReadAt"/> is unset.
    /// Never persisted (see <see cref="IsOwned"/> for the filter-probe convention).
    /// </summary>
    public bool IsUnread { get; set; }

    public bool IsWishlisted { get; set; }
}
