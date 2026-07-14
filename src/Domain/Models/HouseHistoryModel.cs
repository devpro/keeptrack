using System;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

public class HouseHistoryModel : IHasIdAndOwnerId
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string HouseId { get; set; }

    public required DateOnly HistoryDate { get; set; }

    public required HouseEventType EventType { get; set; }

    public string? Description { get; set; }

    public double? Cost { get; set; }

    /// <summary>
    /// Contractor/technician/utility company/store name - a single field covering every category, unlike
    /// Car's Refuel-only StationBrandName vs Maintenance-only Garage split, since House has no event type
    /// where "who was involved" doesn't apply.
    /// </summary>
    public string? Provider { get; set; }
}
