using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// TV Show history transfer object.
/// </summary>
public class TvShowDto : IHasId, IReferenceLinkedDto
{
    /// <summary>
    /// TV Show ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// TV Show title.
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Stable id of the TV Time item this show was imported from, if any. Managed server-side by the
    /// import; round-tripped on edits so it is never lost, but not meant to be set by clients.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? LastEpisodeSeen { get; set; }

    /// <summary>
    /// Id of the shared reference-data document (episode titles, synopsis) for this show, once resolved.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover/poster image URL from the linked reference document - read-only, hydrated server-side on
    /// list reads and never accepted from client input.
    /// </summary>
    public string? ImageUrl { get; set; }

    public TvShowStatus? State { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }
}
