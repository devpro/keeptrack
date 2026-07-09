using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Estimated next maintenance due date, assuming a fixed 1-year cadence from the last recorded maintenance event.
/// </summary>
public class NextMaintenanceDto
{
    /// <summary>
    /// Date of the last recorded maintenance event.
    /// </summary>
    public required DateOnly LastMaintenanceDate { get; set; }

    /// <summary>
    /// Estimated due date for the next maintenance.
    /// </summary>
    public required DateOnly DueDate { get; set; }

    /// <summary>
    /// Months remaining until the due date (negative if overdue).
    /// </summary>
    public required int MonthsRemaining { get; set; }
}
