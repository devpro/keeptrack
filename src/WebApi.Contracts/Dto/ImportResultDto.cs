using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Result of a TV Time GDPR export import.
/// </summary>
public class ImportResultDto
{
    public int ShowsCreated { get; set; }

    /// <summary>
    /// Items already present, matched by their stable TV Time id and left untouched, so a re-import never overwrites or duplicates them.
    /// </summary>
    public int ShowsSkipped { get; set; }

    public int EpisodesCreated { get; set; }

    public int EpisodesSkipped { get; set; }

    public int MoviesCreated { get; set; }

    public int MoviesSkipped { get; set; }

    /// <summary>
    /// Non-fatal issues met during the import, such as a movie referenced only by an unresolvable id.
    /// </summary>
    public List<string> Warnings { get; set; } = [];
}
