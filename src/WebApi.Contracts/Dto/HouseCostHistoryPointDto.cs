using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Total cost of ownership for one calendar year, both as a single total and broken down by event category.
/// </summary>
public class HouseCostHistoryPointDto
{
    /// <summary>
    /// Calendar year this point covers.
    /// </summary>
    public required int Year { get; set; }

    /// <summary>
    /// Combined spend for the year.
    /// </summary>
    public required double TotalCost { get; set; }

    /// <summary>
    /// Spend broken down by event category.
    /// </summary>
    public required List<HouseCategoryCostDto> CostByCategory { get; set; }
}
