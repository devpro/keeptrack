using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

public class MovieDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    /// <summary>
    /// Stable id of the TV Time item this movie was imported from, if any. Managed server-side by the
    /// import; round-tripped on edits so it is never lost, but not meant to be set by clients.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Id of the shared reference-data document (synopsis) for this movie, once resolved.
    /// </summary>
    public string? ReferenceId { get; set; }

    public DateOnly? FirstSeenAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }
}
