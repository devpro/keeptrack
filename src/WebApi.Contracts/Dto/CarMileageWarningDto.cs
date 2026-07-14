namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Flags a car history entry whose recorded mileage doesn't reconcile with its neighbors. Advisory only - the
/// entry is never excluded from metrics or corrected automatically; the user reviews and fixes it themselves.
/// </summary>
public class CarMileageWarningDto
{
    /// <summary>
    /// ID of the flagged car history entry.
    /// </summary>
    public required string CarHistoryId { get; set; }

    /// <summary>
    /// Human-readable explanation of the mismatch.
    /// </summary>
    public required string Message { get; set; }
}
