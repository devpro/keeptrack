using System;
using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// House history data transfer object.
/// </summary>
public class HouseHistoryDto : IHasId
{
    /// <summary>
    /// History ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// House ID.
    /// </summary>
    public required string HouseId { get; set; }

    /// <summary>
    /// History date.
    /// </summary>
    public required DateOnly HistoryDate { get; set; }

    /// <summary>
    /// Event type (Maintenance, Installation, Rework, Purchase, Bill, Other).
    /// </summary>
    public required HouseEventType EventType { get; set; }

    /// <summary>
    /// Free-text description of what was done.
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Total cost of this event.
    /// </summary>
    public double? Cost { get; set; }

    /// <summary>
    /// Contractor/technician/utility company/store name.
    /// </summary>
    public string? Provider { get; set; }
}
