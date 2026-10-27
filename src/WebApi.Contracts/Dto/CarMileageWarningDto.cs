namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Flags a car history entry whose mileage does not reconcile with its neighbors.
/// Advisory only: the entry is never excluded from metrics nor corrected, and the user reviews and fixes it.
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
