using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Computed metrics for one house: yearly cost history.
/// </summary>
public class HouseMetricsDto
{
    /// <summary>
    /// Total cost of ownership, by year.
    /// </summary>
    public required List<HouseCostHistoryPointDto> CostHistory { get; set; }
}
