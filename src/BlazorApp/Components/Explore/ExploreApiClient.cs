using System.Net.Http.Json;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Explore;

/// <summary>
/// Talks to the Explore endpoints (<c>api/explore/{type}</c>) for listing and dismissing suggestions.
/// <paramref name="type"/> is a <see cref="ReferenceItemType"/> member name ("Movie"/"TvShow"). Adding a
/// suggestion goes through the ordinary collection create endpoints, reusing their create + auto-resolve +
/// quota rather than a bespoke Explore add path.
/// </summary>
public sealed class ExploreApiClient(HttpClient http)
{
    public async Task<List<ExploreSuggestionDto>> GetAsync(string type, int count)
    {
        var result = await http.GetFromJsonAsync<List<ExploreSuggestionDto>>($"/api/explore/{type}?count={count}");
        return result ?? [];
    }

    /// <summary>
    /// Adds a suggestion to the caller's collection: the server creates the item and links it to the reference
    /// resolved from the exact TMDB id. Throws on a non-success status (e.g. 403 over the free-preview quota).
    /// </summary>
    public async Task AddAsync(string type, string externalId, string? title, int? year)
    {
        var response = await http.PostAsJsonAsync($"/api/explore/{type}/add/{externalId}", new ExploreAddRequestDto { Title = title, Year = year });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Hides a title from the caller's Explore list.</summary>
    public async Task DismissAsync(string type, string externalId) =>
        (await http.PostAsync($"/api/explore/{type}/dismiss/{externalId}", null)).EnsureSuccessStatusCode();
}
