using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

public class HouseMetricsModel
{
    public required List<HouseCostHistoryPointModel> CostHistory { get; set; }

    public required List<HouseLastRecordModel> LastRecords { get; set; }
}

/// <summary>
/// When each kind of house event was last logged, one line per <see cref="HouseEventType"/>.
/// Same shape as <see cref="CarLastRecordModel"/> and <see cref="HealthLastVisitModel"/>.
/// </summary>
public class HouseLastRecordModel
{
    public required HouseEventType EventType { get; set; }

    public required DateOnly LastDate { get; set; }
}
