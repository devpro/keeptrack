using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// A TV show the user watches or watched.
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
    /// Stable id of the TV Time item this show was imported from, if any.
    /// Managed by the import and round-tripped on edits so it is never lost, but never set by clients.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    public string? LastEpisodeSeen { get; set; }

    /// <summary>
    /// Id of the linked reference document (episode guide, synopsis), once resolved.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover image URL from the linked reference, read-only, hydrated server side on list reads and never accepted from the client.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// The linked reference's primary rating (TMDB or IMDb), on <see cref="ReferenceRatingScale"/>.
    /// Managed by the server on link and refresh, round-tripped on edits, and null until linked.
    /// The full breakdown is <see cref="TvShowReferenceDto.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (10 for TMDB and IMDb), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> came from ("tmdb", "imdb", "igdb"), so the value is labelled rather than a bare number.
    /// Managed by the server on link and refresh, and round-tripped on edits.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    public TvShowStatus? State { get; set; }

    public bool IsFavorite { get; set; }

    /// <summary>
    /// Every owned copy of this show, which counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version.
    /// Never set on a returned item (see <see cref="VideoGameDto.Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }

    public bool IsWishlisted { get; set; }
}
