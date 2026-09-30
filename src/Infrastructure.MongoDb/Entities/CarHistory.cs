using System;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class CarHistory : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("car_id")]
    public required string CarId { get; set; }

    [BsonElement("history_date")]
    public required DateTime HistoryDate { get; set; }

    public double? Mileage { get; set; }

    [BsonElement("event_type")]
    public required CarHistoryType EventType { get; set; }

    public string? Description { get; set; }

    public double? Cost { get; set; }

    public CarHistoryLocation? Location { get; set; }

    public CarHistoryFuel? Fuel { get; set; }

    /// <summary>
    /// Reference into the shared <c>car_station</c> collection - replaces the old embedded
    /// <c>station.brand_name</c> sub-document, which duplicated the station's identity (and, alongside it,
    /// its whole location) on every single refuel.
    /// </summary>
    [BsonElement("station_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? StationId { get; set; }

    public string? Garage { get; set; }
}
