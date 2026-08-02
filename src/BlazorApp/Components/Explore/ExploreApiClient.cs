using System.Net.Http.Json;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Explore;

/// <summary>
/// Talks to the Explore endpoints (<c>api/explore/{type}</c>) for listing, adding and dismissing
/// suggestions. <c>type</c> is a <see cref="ReferenceItemType"/> member name ("Movie"/"TvShow"/"VideoGame").
/// </summary>
public sealed class ExploreApiClient(HttpClient http)
{
    /// <summary>
    /// One page of suggestions. <paramref name="after"/> is the previous page's <c>NextCursor</c> (null for
    /// the first page); a response whose own cursor is null means the ranking is exhausted. A page can come
    /// back shorter than <paramref name="count"/> and still have more behind it - the server filters out what
    /// the caller already tracks after reading the ranking.
    /// </summary>
    public async Task<ExploreSuggestionPageDto> GetAsync(string type, int count, int? after = null)
    {
        var cursor = after is null ? string.Empty : $"&after={after}";
        var result = await http.GetFromJsonAsync<ExploreSuggestionPageDto>($"/api/explore/{type}?count={count}{cursor}");
        return result ?? new ExploreSuggestionPageDto();
    }

    /// <summary>
    /// Adds a suggestion to the caller's collection: the server creates the item and links it to the reference
    /// resolved from the exact provider id. Throws on a non-success status (e.g. 403 over the free-preview
    /// quota, or on a member-only domain).
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
