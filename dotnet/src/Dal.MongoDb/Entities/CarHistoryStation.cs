using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public partial class CarHistoryStation
{
    [BsonElement("brand_name")]
    public string BrandName { get; set; }
}
