using System;
using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Shared, owner-less show metadata collection (<c>tvshow_reference</c>). Deliberately has no
/// <c>owner_id</c> - see <see cref="Keeptrack.Domain.Models.TvShowReferenceModel"/> for why.
/// </summary>
public class TvShowReference
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public required string Title { get; set; }

    [BsonElement("title_normalized")]
    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    [BsonElement("external_ids")]
    public required Dictionary<string, string> ExternalIds { get; set; }

    public List<ReferenceEpisode> Episodes { get; set; } = [];

    [BsonElement("last_enriched_at")]
    public DateTime? LastEnrichedAt { get; set; }
}
