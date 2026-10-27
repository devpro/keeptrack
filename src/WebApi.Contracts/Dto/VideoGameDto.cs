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
    /// Every platform this game is tracked on, one entry per platform rather than per physical copy.
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
    /// The cover shown on the list page: <see cref="CustomImageUrl"/> when set, else the linked reference's cover.
    /// Read-only, hydrated server side on list reads and never accepted from the client, which edits <see cref="CustomImageUrl"/> instead.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// The linked reference's primary rating, from the source the admin selected, on <see cref="ReferenceRatingScale"/>.
    /// Managed by the server on link and refresh, round-tripped on edits, and null until linked.
    /// The full breakdown is <see cref="VideoGameReferenceDto.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/>, null when there is no reference rating.</summary>
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

    /// <summary>
    /// Filter-only query parameter: matches games with at least one platform entry, a game's copies.
    /// Never set on a returned game (see <see cref="Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches when any entry in <see cref="Platforms"/> has this platform.
    /// Never set on a returned game: the list endpoint binds query filters onto this DTO, so this property only receives <c>?platform=</c>.
    /// </summary>
    public string? Platform { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches when any entry in <see cref="Platforms"/> has this state.
    /// Never set on a returned game (see <see cref="Platform"/>).
    /// </summary>
    public string? State { get; set; }
}
