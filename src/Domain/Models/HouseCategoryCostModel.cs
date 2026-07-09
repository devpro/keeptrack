namespace Keeptrack.Domain.Models;

public class HouseCategoryCostModel
{
    public required HouseEventType EventType { get; set; }

    public required double Cost { get; set; }
}
