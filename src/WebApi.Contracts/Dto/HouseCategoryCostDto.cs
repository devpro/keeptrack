namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Total cost for one house history event category within a <see cref="HouseCostHistoryPointDto"/>.
/// </summary>
public class HouseCategoryCostDto
{
    /// <summary>
    /// Event category.
    /// </summary>
    public required HouseEventType EventType { get; set; }

    /// <summary>
    /// Total cost for this category.
    /// </summary>
    public required double Cost { get; set; }
}
