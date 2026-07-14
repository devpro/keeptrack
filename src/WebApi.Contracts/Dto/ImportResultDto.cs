using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of a TV Time GDPR export import.
/// </summary>
public class ImportResultDto
{
    public int ShowsCreated { get; set; }

    /// <summary>
    /// Items already present (matched by their stable TV Time id) and therefore left untouched -
    /// re-importing the same export never overwrites or duplicates what a previous import created.
    /// </summary>
    public int ShowsSkipped { get; set; }

    public int EpisodesCreated { get; set; }

    public int EpisodesSkipped { get; set; }

    public int MoviesCreated { get; set; }

    public int MoviesSkipped { get; set; }

    /// <summary>
    /// Non-fatal issues encountered during the import (e.g. a movie referenced only by an unresolvable id).
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
