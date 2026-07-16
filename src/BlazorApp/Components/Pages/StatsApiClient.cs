using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Pages;

/// <summary>
/// Backs the Home page's collection overview - lives next to <c>Home.razor</c> per the feature-folder
/// convention for non-CRUD pages.
/// </summary>
public sealed class StatsApiClient(HttpClient http)
{
    public async Task<CollectionStatsDto?> GetAsync() =>
        await http.GetFromJsonAsync<CollectionStatsDto>("/api/stats");
}
