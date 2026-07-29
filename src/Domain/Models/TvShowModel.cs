using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class TvShowModel : IHasIdAndOwnerId, IHasTvTimeId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Title { get; set; }

    /// <summary>
    /// Stable identifier for the item this record was imported from (TV Time's own show id, or a
    /// title-derived fallback when the export carries none). Set once at import time and never rewritten
    /// by reference enrichment, so a re-import matches by this id instead of the enrichment-mutable Title
    /// and can't create a duplicate. Null for shows created outside the import.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? LastEpisodeSeen { get; set; }

    public string? ReferenceId { get; set; }

    /// <summary>
    /// Denormalized copy of the linked reference's primary-source (TMDB) rating value, on a 0-10 scale
    /// given by <see cref="ReferenceRatingScale"/>. Copied down on link/refresh for fast list display and
    /// sorting; the authoritative multi-source data is on <see cref="TvShowReferenceModel.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (10 for TMDB); null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    public TvShowStatus? State { get; set; }

    public bool IsFavorite { get; set; }

    public List<OwnedVersionModel> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only: matches if <see cref="OwnedVersions"/> is non-empty. Never persisted - see
    /// <see cref="MovieModel.IsOwned"/>.
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }
}
