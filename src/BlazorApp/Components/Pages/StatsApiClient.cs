using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Pages;

/// <summary>
/// Backs the Home page's collection overview, next to <c>Home.razor</c> as non-CRUD pages keep their client in their feature folder.
/// </summary>
public sealed class StatsApiClient(HttpClient http)
{
    public async Task<CollectionStatsDto?> GetAsync() =>
        await http.GetFromJsonAsync<CollectionStatsDto>("/api/stats");
}
