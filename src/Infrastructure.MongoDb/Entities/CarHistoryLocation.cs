using System.Collections.Generic;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class CarHistoryLocation
{
    public required string City { get; set; }

    [BsonElement("postal_code")]
    public string? PostalCode { get; set; }

    public string? Country { get; set; }

    public List<double>? Coordinates { get; set; }
}
