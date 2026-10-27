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
    /// The cover shown on the list page: <see cref="CustomImageUrl"/> when set, else the linked reference's cover.
    /// Read-only, hydrated server side on list reads and never accepted from the client, which edits <see cref="CustomImageUrl"/> instead.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// The linked reference's primary rating (Discogs, 0 to 5), on <see cref="ReferenceRatingScale"/>.
    /// Managed by the server on link and refresh, round-tripped on edits, and null until linked.
    /// The full breakdown is <see cref="AlbumReferenceDto.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (5 for Discogs), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> came from ("tmdb", "imdb", "igdb"), so the value is labelled rather than a bare number.
    /// Managed by the server on link and refresh, and round-tripped on edits.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    /// <summary>
    /// The tenant's own cover, freely editable, which takes priority over the linked reference's cover wherever one is shown.
    /// Null means the reference's cover, if any.
    /// </summary>
    public string? CustomImageUrl { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this album, which counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version.
    /// Never set on a returned item (see <see cref="VideoGameDto.Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }
}
