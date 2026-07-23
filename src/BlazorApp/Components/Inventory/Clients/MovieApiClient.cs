using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class MovieApiClient(HttpClient http)
    : InventoryApiClientBase<MovieDto>(http)
{
    protected override string ApiResourceName => "/api/movies";

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection
    /// (POST api/movies/{id}/refresh-reference on WebApi). Returns the (possibly now-linked) item so the
    /// caller can tell whether a match was actually found.
    /// </summary>
    public async Task<MovieDto> RefreshReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<MovieDto>())!;
    }

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document
    /// (POST api/movies/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<MovieDto> UnlinkReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<MovieDto>())!;
    }
}
