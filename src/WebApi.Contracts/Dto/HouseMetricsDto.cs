using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one house: yearly cost history and a last-record-per-type readout.
/// </summary>
public class HouseMetricsDto
{
    /// <summary>
    /// Total cost of ownership, by year.
    /// </summary>
    public required List<HouseCostHistoryPointDto> CostHistory { get; set; }

    /// <summary>
    /// When each event type was last recorded, most recent first.
    /// </summary>
    public required List<HouseLastRecordDto> LastRecords { get; set; }
}

/// <summary>
/// When a house history event type was last recorded.
/// </summary>
public class HouseLastRecordDto
{
    /// <summary>
    /// The event type.
    /// </summary>
    public required HouseEventType EventType { get; set; }

    /// <summary>
    /// The most recent recorded date for that event type.
    /// </summary>
    public required DateOnly LastDate { get; set; }
}
