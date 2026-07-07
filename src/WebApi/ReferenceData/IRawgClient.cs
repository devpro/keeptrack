using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// One RAWG search hit - title, year and cover art, enough for automatic matching or for an admin
/// to pick from when a match is ambiguous.
/// </summary>
public record RawgSearchResult(string ExternalId, string Title, int? Year, string? ImageUrl);

public record RawgGameDetails(string ExternalId, string Title, int? Year, string? Synopsis, List<string> Genres, List<string> Platforms, string? ImageUrl);

/// <summary>
/// Thin wrapper over the RAWG Video Games Database REST API. Interface exists so tests use a fake -
/// never call the real RAWG API from a test.
/// </summary>
public interface IRawgClient
{
    Task<IReadOnlyList<RawgSearchResult>> SearchGamesAsync(string title, int? year, CancellationToken cancellationToken = default);

    Task<RawgGameDetails?> GetGameDetailsAsync(string externalId, CancellationToken cancellationToken = default);
}
