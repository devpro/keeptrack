namespace Keeptrack.Domain.Models;

/// <summary>
/// One physical fuel station, shared by every tenant rather than owned by one.
/// </summary>
/// <remarks>
/// This is the same deliberate exception to "every collection has an owner_id" as the <c>*_reference</c>
/// collections, and for the same reason: a station at a given address is a public fact, not one account's
/// data. Car history entries point at it by id instead of each carrying their own copy of the brand name,
/// city, postal code and coordinates - which is what made every refuel at the same station re-type (and
/// re-store) the identical location.
/// </remarks>
public class CarStationModel
{
    public string? Id { get; set; }

    /// <summary>Brand/retailer name, e.g. "TotalEnergies" - the "Distributeur" column of the Excel import.</summary>
    public required string BrandName { get; set; }

    public string? City { get; set; }

    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    public double? Longitude { get; set; }

    public double? Latitude { get; set; }

    /// <summary>
    /// Lower-cased, trimmed <see cref="BrandName"/>, written by the repository on every upsert. Together
    /// with <see cref="CityNormalized"/> and <see cref="PostalCode"/> it is the natural key a unique index
    /// enforces, so two members creating "Total" and "total " inline end up on one document rather than two.
    /// </summary>
    public string BrandNameNormalized { get; set; } = "";

    /// <summary>Normalized <see cref="City"/> - see <see cref="BrandNameNormalized"/>.</summary>
    public string CityNormalized { get; set; } = "";
}
