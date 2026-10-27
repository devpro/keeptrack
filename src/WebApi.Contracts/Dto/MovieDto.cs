using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

public class MovieDto : IHasId, IReferenceLinkedDto
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    /// <summary>
    /// Stable id of the TV Time item this movie was imported from, if any.
    /// Managed by the import and round-tripped on edits so it is never lost, but never set by clients.
    /// </summary>
    public string? TvTimeId { get; set; }

    public int? Year { get; set; }

    public float? Rating { get; set; }

    public string? Notes { get; set; }

    /// <summary>
    /// Id of the linked reference document (synopsis, cast), once resolved.
    /// </summary>
    public string? ReferenceId { get; set; }

    /// <summary>
    /// Cover image URL from the linked reference, read-only, hydrated server side on list reads and never accepted from the client.
    /// </summary>
    public string? ImageUrl { get; set; }

    /// <summary>
    /// The linked reference's primary rating (TMDB or IMDb), on <see cref="ReferenceRatingScale"/>, managed by the server on link and refresh.
    /// Round-tripped on edits so a save does not drop it, never set by clients, and null until linked.
    /// The full breakdown is <see cref="MovieReferenceDto.Ratings"/>.
    /// </summary>
    public double? ReferenceRating { get; set; }

    /// <summary>Scale of <see cref="ReferenceRating"/> (10 for TMDB and IMDb), null when there is no reference rating.</summary>
    public double? ReferenceRatingScale { get; set; }

    /// <summary>
    /// The rating source <see cref="ReferenceRating"/> came from ("tmdb", "imdb", "igdb"), so the value is labelled rather than a bare number.
    /// Managed by the server on link and refresh, and round-tripped on edits.
    /// </summary>
    public string? ReferenceRatingSource { get; set; }

    public DateOnly? FirstSeenAt { get; set; }

    public bool IsFavorite { get; set; }

    public bool WantToWatch { get; set; }

    /// <summary>
    /// Every owned copy of this movie, which counts as owned when this list is non-empty.
    /// </summary>
    public List<OwnedVersionDto> OwnedVersions { get; set; } = [];

    /// <summary>
    /// Filter-only query parameter: matches items with at least one owned version.
    /// Never set on a returned item (see <see cref="VideoGameDto.Platform"/>).
    /// </summary>
    public bool IsOwned { get; set; }

    /// <summary>
    /// Filter-only query parameter: matches items with no <see cref="FirstSeenAt"/> set.
    /// Never set on a returned item (see <see cref="IsOwned"/>).
    /// </summary>
    public bool IsUnseen { get; set; }

    public bool IsWishlisted { get; set; }
}
