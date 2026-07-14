using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class CarHistoryFuel
{
    public string? Category { get; set; }

    public double? Volume { get; set; }

    [BsonElement("unit_price")]
    public double? UnitPrice { get; set; }

    [BsonElement("electric_volume")]
    public double? ElectricVolume { get; set; }

    [BsonElement("electric_unit_price")]
    public double? ElectricUnitPrice { get; set; }

    [BsonElement("is_full_refill")]
    public bool? IsFullRefill { get; set; }

    [BsonElement("delta_mileage")]
    public double? DeltaMileage { get; set; }
}
