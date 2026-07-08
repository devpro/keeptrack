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

    public TvShowStatus? State { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }
}
