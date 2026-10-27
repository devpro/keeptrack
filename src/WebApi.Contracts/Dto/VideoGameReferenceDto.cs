using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Shared video game metadata (synopsis, cover, platforms), read-only and fetched apart from <see cref="VideoGameDto"/>, since it is not the tenant's own data.
/// </summary>
public class VideoGameReferenceDto : IHasId
{
    public string? Id { get; set; }

    public string? Title { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    public List<string> Platforms { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    /// <summary>Aggregate ratings keyed by source ("igdb", "igdbcritic", "rawg", "metacritic"), see <see cref="ReferenceRatingDto"/>.</summary>
    public Dictionary<string, ReferenceRatingDto> Ratings { get; set; } = [];

    public string? ImageUrl { get; set; }
}
