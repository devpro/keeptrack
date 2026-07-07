using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A music album the user has listened to or wants to listen to.
/// </summary>
public class AlbumDto : IHasId
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

    public bool IsFavorite { get; set; }
}
