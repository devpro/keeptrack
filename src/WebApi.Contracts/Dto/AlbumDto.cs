using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A music album the user has listened to or wants to listen to.
/// </summary>
public class AlbumDto : IHasId, IReferenceLinkedDto
{
    /// <summary>
    /// Unique identifier.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Album title.
    /// </summary>
    /// <example>The Dark Side of the Moon</example>
    public string? Title { get; set; }

    /// <summary>
    /// Artist or band name.
    /// </summary>
    /// <example>Pink Floyd</example>
    public string? Artist { get; set; }

    /// <summary>
    /// Release year.
    /// </summary>
    public int? Year { get; set; }

    /// <summary>
    /// Musical genre.
    /// </summary>
    public string? Genre { get; set; }

    /// <summary>
    /// User rating, from 0 to 5.
    /// </summary>
    public float? Rating { get; set; }

    /// <summary>
    /// Id of the linked <c>album_reference</c> document, when a match has been found.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover/poster image URL from the linked reference document - read-only, hydrated server-side on
    /// list reads and never accepted from client input.
    /// </summary>
    public string? ImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this album - the album counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version. Never populated on a
    /// returned item - see <see cref="VideoGameDto.Platform"/> for the convention.
    /// </summary>
    public bool IsOwned { get; set; }
}
