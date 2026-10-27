using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class MovieModel : IHasIdAndOwnerId, IHasTvTimeId, IReferenceLinkedModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// Stable id of the TV Time item this record was imported from: the movie's tracking uuid, or a title-derived fallback when the export has none.
    /// Set once at import and never rewritten by reference resolution, so a re-import matches by it rather than by a title resolution may change.
    /// Null for movies created outside the import.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// The linked reference's primary rating (TMDB or IMDb, 0 to 10), on <see cref="ReferenceRatingScale"/>.
    /// Copied on link and refresh so a list displays and sorts without a join.
    /// The authoritative data is <see cref="MovieReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (10 for TMDB and IMDb), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> was taken from, a <c>RatingSourceCatalog</c> key ("tmdb", "imdb", "igdb").
    /// Stamped on every link and refresh, even when that source has no value for this reference.
    /// It records which source the copy was computed from, which is how the admin recompute tells an item already on the selected source from one needing a new stamp.
    /// Null on an item never stamped, which the recompute counts as different.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    public DateOnly? FirstSeenAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter only: matches when <see cref="OwnedVersions"/> is non-empty.
    /// Never persisted, since ownership derives from holding at least one copy.
    /// See <see cref="VideoGameModel.Platform"/> for the filter-probe convention.
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter only: matches when <see cref="FirstSeenAt"/> is unset.
    /// Never persisted (see <see cref="IsOwned"/> for the filter-probe convention).
    /// </summary>
    public bool IsUnseen { get; set; }

    public bool IsWishlisted { get; set; }
}
