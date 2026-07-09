using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class Car : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("commercial_name")]
    public required string Name { get; set; }

    public string? Manufacturer { get; set; }

    public string? Model { get; set; }

    public int? Year { get; set; }

    [BsonElement("license_plate")]
    public string? LicensePlate { get; set; }

    [BsonElement("energy_type")]
    public required CarEnergyType EnergyType { get; set; }
}
