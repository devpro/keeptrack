using System;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

public class HealthRecord : IHasIdAndOwnerId
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("owner_id")]
    public required string OwnerId { get; set; }

    [BsonElement("health_profile_id")]
    public required string HealthProfileId { get; set; }

    [BsonElement("history_date")]
    public required DateTime HistoryDate { get; set; }

    [BsonElement("event_type")]
    public required HealthEventType EventType { get; set; }

    public string? Specialty { get; set; }

    public string? Practitioner { get; set; }

    public string? Description { get; set; }

    public string? Notes { get; set; }

    public double? Price { get; set; }

    [BsonElement("public_reimbursement")]
    public double? PublicReimbursement { get; set; }

    [BsonElement("insurance_reimbursement")]
    public double? InsuranceReimbursement { get; set; }

    [BsonElement("not_covered")]
    public double? NotCovered { get; set; }
}
