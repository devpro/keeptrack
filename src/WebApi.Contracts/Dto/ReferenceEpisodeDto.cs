using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One episode's reference metadata (title, air date) from the shared reference collection.
/// </summary>
public class ReferenceEpisodeDto
{
    public required int SeasonNumber { get; set; }

    public required int EpisodeNumber { get; set; }

    public required string Title { get; set; }

    public DateOnly? AirDate { get; set; }
}
