using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// Estimated next maintenance due date, assuming a fixed 1-year cadence from the last recorded maintenance
/// event. Only ever produced when a maintenance history actually exists - see CarMetricsService.
/// </summary>
public class NextMaintenanceModel
{
    public required DateOnly LastMaintenanceDate { get; set; }

    public required DateOnly DueDate { get; set; }

    public required int MonthsRemaining { get; set; }
}
