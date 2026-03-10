using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Infrastructure.MongoDb.Entities;

public class CarHistoryStation
{
    [BsonElement("brand_name")]
    public required string BrandName { get; set; }
}
