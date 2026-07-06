using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Episode data transfer object.
/// </summary>
public class EpisodeDto : IHasId
{
    /// <summary>
    /// Episode ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// TV Show ID.
    /// </summary>
    public required string TvShowId { get; set; }

    /// <summary>
    /// Season number.
    /// </summary>
    public required int SeasonNumber { get; set; }

    /// <summary>
    /// Episode number within the season.
    /// </summary>
    public required int EpisodeNumber { get; set; }

    /// <summary>
    /// Date the episode was watched.
    /// </summary>
    public DateOnly? WatchedAt { get; set; }

    public string? Notes { get; set; }
}
