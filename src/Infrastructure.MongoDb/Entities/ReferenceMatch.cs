namespace Keeptrack.Infrastructure.MongoDb.Entities;

/// <summary>
/// Embedded in every reference entity (see <see cref="Keeptrack.Domain.Models.ReferenceMatchModel"/>).
/// </summary>
public class ReferenceMatch
{
    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// Null for TV shows, movies and video games, whose match key has no creator.
    /// The global <c>IgnoreIfNullConvention</c> omits a null from the document, so no <c>[BsonIgnoreIfNull]</c> is needed.
    /// Older documents store <c>""</c> rather than omitting the field (see <c>MergeMatchedAliases</c>).
    /// </summary>
    public string? Creator { get; set; }

    /// <summary>Null for every domain but books (see <see cref="Keeptrack.Domain.Models.ReferenceMatchModel.Isbn"/>).</summary>
    public string? Isbn { get; set; }
}
