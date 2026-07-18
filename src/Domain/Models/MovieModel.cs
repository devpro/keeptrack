using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class MovieModel : IHasIdAndOwnerId, IHasTvTimeId
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
