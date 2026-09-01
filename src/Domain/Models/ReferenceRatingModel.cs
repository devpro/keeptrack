namespace Keeptrack.Domain.Models;

/// <summary>
/// One aggregate rating for a reference item from a single source, stored in a reference model's
/// <c>Ratings</c> dictionary keyed by that source (e.g. "tmdb", and later "imdb", "metacritic").
/// <see cref="Value"/> is on the source's own <see cref="Scale"/> (TMDB is out of 10, RAWG out of 5,
/// Metacritic out of 100) and is never normalized, so a source's native precision is preserved.
/// A single list only ever mixes items from one source, so its raw values still sort apples-to-apples.
/// The whole dictionary lives on the shared, user-agnostic reference document (the source of truth);
/// the tenant's own item carries only a denormalized copy of the primary source's value for fast list
/// display and sorting - see <see cref="MovieModel.ReferenceRating"/>.
/// </summary>
public class ReferenceRatingModel
{
    public required double Value { get; set; }

    public required double Scale { get; set; }

    public int? Count { get; set; }
}
