using System;
using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace KeepTrack.Dal.MongoDb.Entities;

public partial class CarHistory : IEntity
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("owner_id")]
    public string OwnerId { get; set; }

    [BsonElement("car_id")]
    public string CarId { get; set; }

    [BsonElement("history_date")]
    public DateTime HistoryDate { get; set; }

    public double Mileage { get; set; }

    public string Action { get; set; }

    public CarHistoryLocation? Location { get; set; }

    public List<double>? Coordinates { get; set; }

    public CarHistoryFuel? Fuel { get; set; }

    public CarHistoryStation? Station { get; set; }
}
