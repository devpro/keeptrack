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
    /// Stable identifier for the item this record was imported from (TV Time's own per-movie tracking
    /// uuid, or a title-derived fallback when the export carries none). Set once at import time and never
    /// rewritten by reference enrichment, so a re-import matches by this id instead of the
    /// enrichment-mutable Title and can't create a duplicate. Null for movies created outside the import.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Denormalized copy of the linked reference's primary-source rating value (TMDB's, on a 0-10 scale
    /// given by <see cref="ReferenceRatingScale"/>). Copied down from the shared reference document on
    /// link/refresh purely so the list page can display and sort by it without a per-page join; the
    /// authoritative multi-source data lives on <see cref="MovieReferenceModel.Ratings"/>. Null until linked.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (10 for TMDB); null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// Which rating source <see cref="ReferenceRating"/> was taken from ("tmdb", "imdb", "rawg", ...) - see
    /// <c>RatingSourceCatalog</c>. Stamped on every link/refresh, and stamped even when that source has no
    /// value for this reference: it records which source the denormalized copy was computed from, not where a
    /// number came from, which is what lets the admin "recompute" action tell an item that is already on the
    /// selected source from one that still needs re-stamping. Null only for items linked before this existed.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    public DateOnly? FirstSeenAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only: matches if <see cref="OwnedVersions"/> is non-empty. Never persisted - ownership is
    /// derived from owning at least one version, not stored as its own flag. See
    /// <see cref="VideoGameModel.Platform"/> for the filter-probe convention.
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only: matches if <see cref="FirstSeenAt"/> is unset. Never persisted - see
    /// <see cref="IsOwned"/> for the filter-probe convention.
    /// </summary>
    public bool IsUnseen { get; set; }

    public bool IsWishlisted { get; set; }
}
