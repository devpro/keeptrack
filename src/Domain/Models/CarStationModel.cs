namespace Keeptrack.Domain.Models;

/// <summary>
/// One physical fuel station, shared by every tenant rather than owned by one.
/// </summary>
/// <remarks>
/// The same exception to "every collection has an owner_id" as the <c>*_reference</c> collections, for the same reason: a station at an address is a public fact, not one account's data.
/// Car history entries point at it by id rather than each carrying the brand, city, postal code and coordinates, so a station's location is typed and stored once.
/// </remarks>
public class CarStationModel
{
    public string? Id { get; set; }

    /// <summary>Brand or retailer name, such as "TotalEnergies".</summary>
    public required string BrandName { get; set; }

    public string? City { get; set; }

    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    public double? Longitude { get; set; }

    public double? Latitude { get; set; }

    /// <summary>
    /// Lower-cased, trimmed <see cref="BrandName"/>, written by the repository on every upsert.
    /// With <see cref="CityNormalized"/> and <see cref="PostalCode"/> it forms the natural key of a unique index, so "Total" and "total " created inline by two members land on one document.
    /// </summary>
    public string BrandNameNormalized { get; set; } = "";

    /// <summary>
    /// Normalized <see cref="City"/>, see <see cref="BrandNameNormalized"/>.
    /// Empty rather than null for a station with no city, or the unique index would collapse every cityless station onto one key.
    /// </summary>
    public string CityNormalized { get; set; } = "";
}
