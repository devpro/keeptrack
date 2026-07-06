using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of a TV Time GDPR export import.
/// </summary>
public class ImportResultDto
{
    public int ShowsCreated { get; set; }

    public int ShowsUpdated { get; set; }

    public int EpisodesCreated { get; set; }

    public int EpisodesUpdated { get; set; }

    public int MoviesCreated { get; set; }

    public int MoviesUpdated { get; set; }

    /// <summary>
    /// Non-fatal issues encountered during the import (e.g. a movie referenced only by an unresolvable id).
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
