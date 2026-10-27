using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// One shared fuel station (see <see cref="Domain.Models.CarStationModel"/> for why it has no <c>owner_id</c>).
/// </summary>
public class CarStation
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("brand_name")]
    public required string BrandName { get; set; }

    public string? City { get; set; }

    [BsonElement("postal_code")]
    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    /// <summary>
    /// [longitude, latitude], like <see cref="CarHistoryLocation.Coordinates"/>.
    /// A real pair or nothing, never an empty list, since readers index [0] and [1].
    /// </summary>
    public List<double>? Coordinates { get; set; }

    [BsonElement("brand_name_normalized")]
    public required string BrandNameNormalized { get; set; }

    [BsonElement("city_normalized")]
    public required string CityNormalized { get; set; }
}
