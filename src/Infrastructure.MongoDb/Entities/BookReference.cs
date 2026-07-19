using System;
using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Shared, owner-less book metadata collection (<c>book_reference</c>). See
/// <see cref="TvShowReference"/> for why this has no <c>owner_id</c>.
/// </summary>
public class BookReference
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public required string Title { get; set; }

    [BsonElement("title_normalized")]
    public required string TitleNormalized { get; set; }

    public int? Year { get; set; }

    public string? Synopsis { get; set; }

    [BsonElement("author_reference_id")]
    public string? AuthorReferenceId { get; set; }

    [BsonElement("external_ids")]
    public required Dictionary<string, string> ExternalIds { get; set; }

    [BsonElement("matched_aliases")]
    public List<ReferenceMatch> MatchedAliases { get; set; } = [];

    public List<string> Genres { get; set; } = [];

    [BsonElement("image_url")]
    public string? ImageUrl { get; set; }

    public string? Language { get; set; }

    [BsonElement("last_enriched_at")]
    public DateTime? LastEnrichedAt { get; set; }
}
