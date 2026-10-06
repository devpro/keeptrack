namespace Keeptrack.Domain.Models;

/// <summary>
/// One aggregate rating from a single source, in a reference's <c>Ratings</c> dictionary keyed by that source ("tmdb", "imdb", "igdb").
/// <see cref="Value"/> stays on the source's own <see cref="Scale"/> (TMDB out of 10, RAWG out of 5, Metacritic out of 100) and is never normalized.
/// A list only sorts by one source, so raw values compare correctly.
/// The dictionary on the reference is the source of truth, and the tenant's item carries a copy of the primary source's value (see <see cref="MovieModel.ReferenceRating"/>).
/// </summary>
public class ReferenceRatingModel
{
    public required double Value { get; set; }

    public required double Scale { get; set; }

    public int? Count { get; set; }
}
