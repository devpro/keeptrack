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
    /// The linked reference's primary rating (Discogs, 0 to 5), on <see cref="ReferenceRatingScale"/>.
    /// Copied on link and refresh so a list displays and sorts without a join.
    /// The authoritative data is <see cref="AlbumReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for Discogs), null when there is no reference rating.</summary>
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
}
