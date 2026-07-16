using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Video Game data transfer object.
/// </summary>
public class VideoGameDto : IHasId, IReferenceLinkedDto
{
    /// <summary>
    /// Video Game ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Video Game title.
    /// </summary>
    public string? Title { get; set; }

    /// <summary>
    /// Every platform this game is tracked on - one entry per platform, not per physical copy.
    /// </summary>
    public List<VideoGamePlatformDto> Platforms { get; set; } = [];

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Id of the linked <c>videogame_reference</c> document, when a match has been found.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover/poster image URL from the linked reference document - read-only, hydrated server-side on
    /// list reads and never accepted from client input.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches games with at least one platform entry (a game's copies).
    /// Never populated on a returned game - see <see cref="Platform"/> for the convention.
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches if any entry in <see cref="Platforms"/> has this platform.
    /// Never populated on a returned game - the list endpoint binds query-string filters onto this DTO
    /// before mapping to the Domain model, so this property exists purely to receive <c>?platform=</c>.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches if any entry in <see cref="Platforms"/> has this state. Never
    /// populated on a returned game - see <see cref="Platform"/>.
    /// </summary>
    public string? State { get; set; }
}
