using System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class OwnedVersion
{
    [BsonElement("copy_type")]
    public CopyType CopyType { get; set; }

    [BsonRepresentation(BsonType.Decimal128)]
    public decimal? Price { get; set; }

    public string? Vendor { get; set; }

    [BsonElement("acquired_at")]
    public DateTime? AcquiredAt { get; set; }

    public string? Reference { get; set; }

    [BsonElement("product_name")]
    public string? ProductName { get; set; }
}
