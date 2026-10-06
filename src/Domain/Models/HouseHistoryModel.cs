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
    /// Contractor, technician, utility company or store name.
    /// One field covers every category, unlike Car's station and garage split, since every house event involves someone.
    /// </summary>
    public string? Provider { get; set; }
}
