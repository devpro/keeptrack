using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.ReferenceData;

/// <summary>
/// Read-only access to the shared reference collection - not per-tenant CRUD, so this doesn't extend
/// <see cref="Keeptrack.BlazorApp.Components.Inventory.Clients.InventoryApiClientBase{TDto}"/>.
/// </summary>
public sealed class ReferenceDataApiClient(HttpClient http)
{
    public async Task<TvShowReferenceDto?> GetTvShowAsync(string referenceId)
    {
        var response = await http.GetAsync($"/api/reference-data/tv-shows/{referenceId}");
        return response.IsSuccessStatusCode ? await response.Content.ReadFromJsonAsync<TvShowReferenceDto>() : null;
    }

    public async Task<MovieReferenceDto?> GetMovieAsync(string referenceId)
    {
        var response = await http.GetAsync($"/api/reference-data/movies/{referenceId}");
        return response.IsSuccessStatusCode ? await response.Content.ReadFromJsonAsync<MovieReferenceDto>() : null;
    }
}
