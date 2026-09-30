namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Outcome of folding one fuel station into another.
/// </summary>
public class CarStationMergeResultDto
{
    /// <summary>
    /// How many car history entries were moved onto the surviving station. Reported rather than assumed:
    /// it is the only visible evidence that the merge re-pointed the entries instead of stranding them.
    /// </summary>
    public long RepointedEntries { get; set; }

    /// <summary>
    /// The surviving station, including anything it gained from the absorbed one.
    /// </summary>
    public CarStationDto? Station { get; set; }
}
