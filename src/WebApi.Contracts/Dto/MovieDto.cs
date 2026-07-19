using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

public class MovieDto : IHasId, IReferenceLinkedDto
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

    /// <summary>
    /// Cover/poster image URL from the linked reference document - read-only, hydrated server-side on
    /// list reads and never accepted from client input.
    /// </summary>
    public string? ImageUrl { get; set; }

    public DateOnly? FirstSeenAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    /// <summary>
    /// Every owned copy of this movie - the movie counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version. Never populated on a
    /// returned item - see <see cref="VideoGameDto.Platform"/> for the convention.
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches items with no <see cref="FirstSeenAt"/> set. Never populated on
    /// a returned item - see <see cref="IsOwned"/> for the convention.
    /// </summary>
    public bool IsUnseen { get; set; }

    public bool IsWishlisted { get; set; }
}
