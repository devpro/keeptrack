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

    [BsonElement("matched_aliases")]
    public List<ReferenceMatch> MatchedAliases { get; set; } = [];

    public List<ReferenceEpisode> Episodes { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    public List<CastMember> Cast { get; set; } = [];

    [BsonElement("poster_url")]
    public string? PosterUrl { get; set; }

    [BsonElement("last_enriched_at")]
    public DateTime? LastEnrichedAt { get; set; }
}
