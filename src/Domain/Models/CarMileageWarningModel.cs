namespace Keeptrack.Domain.Models;

/// <summary>
/// Flags a CarHistory entry whose recorded mileage doesn't reconcile with its neighbors, so the user can fix
/// the underlying entry - see CarMetricsService. Advisory only: the flagged entry is never excluded from
/// metrics or corrected automatically.
/// </summary>
public class CarMileageWarningModel
{
    public required string CarHistoryId { get; set; }

    public required string Message { get; set; }
}
