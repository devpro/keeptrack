using System;

namespace KeepTrack.WebApi.Dto;

/// <summary>
/// Car history data transfer object.
/// </summary>
public class CarHistoryDto
{
    /// <summary>
    /// History ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// Car ID.
    /// </summary>
    public required string CarId { get; set; }

    /// <summary>
    /// History date.
    /// </summary>
    public DateTime HistoryDate { get; set; }

    /// <summary>
    /// Mileage indicated on the car.
    /// </summary>
    public int? Mileage { get; set; }

    /// <summary>
    /// Action made on the car.
    /// </summary>
    public required string Action { get; set; }

    /// <summary>
    /// City.
    /// </summary>
    public string? City { get; set; }

    /// <summary>
    /// Longitude.
    /// </summary>
    public double? Longitude { get; set; }

    /// <summary>
    /// Latitude.
    /// </summary>
    public double? Latitude { get; set; }

    /// <summary>
    /// Fuel category.
    /// </summary>
    public string? FuelCategory { get; set; }

    /// <summary>
    /// Fuel volme (L).
    /// </summary>
    public double? FuelVolume { get; set; }

    /// <summary>
    /// Fuel unit price.
    /// </summary>
    public double? FuelUnitPrice { get; set; }

    /// <summary>
    /// Amount.
    /// </summary>
    public double? Amount { get; set; }

    /// <summary>
    /// Is full tank?
    /// </summary>
    public bool? IsFullTank { get; set; }

    /// <summary>
    /// Delta mileage since last refuel.
    /// </summary>
    public double? DeltaMileage { get; set; }

    /// <summary>
    /// Last refuel history id.
    /// </summary>
    public string? LastRefuelHistoryId { get; set; }

    /// <summary>
    /// Station brand name.
    /// </summary>
    public string? StationBrandName { get; set; }
}
