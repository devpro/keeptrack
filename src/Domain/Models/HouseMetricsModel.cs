using System;
using System.Collections.Generic;

namespace Keeptrack.Domain.Models;

public class HouseMetricsModel
{
    public required List<HouseCostHistoryPointModel> CostHistory { get; set; }

    public required List<HouseLastRecordModel> LastRecords { get; set; }
}

/// <summary>
/// "When did I last log each kind of house event" - one line per <see cref="HouseEventType"/>. Same shape
/// as <see cref="CarLastRecordModel"/>/<see cref="HealthLastVisitModel"/>.
/// </summary>
public class HouseLastRecordModel
{
    public required HouseEventType EventType { get; set; }

    public required DateOnly LastDate { get; set; }
}
