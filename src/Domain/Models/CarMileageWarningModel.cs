namespace Keeptrack.Domain.Models;

/// <summary>
/// Flags a car history entry whose mileage does not reconcile with its neighbors, so the user can fix it (see <c>CarMetricsService</c>).
/// Advisory only: the entry is never excluded from metrics nor corrected automatically.
/// </summary>
public class CarMileageWarningModel
{
    public required string CarHistoryId { get; set; }

    public required string Message { get; set; }
}
