namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One RAWG search hit - title, year and cover art, enough for automatic matching or for an admin
/// to pick from when a match is ambiguous.
/// </summary>
public record RawgSearchResult(string ExternalId, string Title, int? Year, string? ImageUrl);

public record RawgGameDetails(string ExternalId, string Title, int? Year, string? Synopsis, List<string> Genres, List<string> Platforms, string? ImageUrl, double? Rating = null, int? RatingsCount = null, int? Metacritic = null);

/// <summary>
/// One entry from a RAWG "top rated" page - the fields a discovery card needs plus both of RAWG's aggregate
/// scores, so the caller picks whichever the admin selected as the primary source without a second request.
/// RAWG's list response carries no description, so there is no synopsis here (unlike TMDB's, which does).
/// </summary>
public record RawgTopRatedItem(string ExternalId, string Title, int? Year, string? ImageUrl, double? Rating, int? Metacritic);

/// <summary>
/// Thin wrapper over the RAWG Video Games Database REST API. Interface exists so tests use a fake -
/// never call the real RAWG API from a test.
/// </summary>
public interface IRawgClient
{
    Task<IReadOnlyList<RawgSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default);

    Task<RawgGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default);

    /// <summary>
    /// One page of RAWG's best games, highest first, ordered by <paramref name="ratingSource"/> - the source
    /// the Explore discovery feature reads for video games. <paramref name="ratingSource"/> is a
    /// <see cref="RatingSourceCatalog"/> key RAWG can sort on natively (<see cref="RatingSourceCatalog.Rawg"/>
    /// or <see cref="RatingSourceCatalog.Metacritic"/>), so no per-title enrichment call is ever needed to
    /// rank the list - unlike movies/TV, whose IMDb ranking has no provider-side ordering to lean on.
    /// Returns an empty list past the last page.
    /// </summary>
    Task<IReadOnlyList<RawgTopRatedItem>> GetTopRatedGamesAsync(int page, string ratingSource, CancellationToken cancellationToken = default);
}
