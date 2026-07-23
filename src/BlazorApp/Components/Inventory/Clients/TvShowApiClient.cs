using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class TvShowApiClient(HttpClient http)
    : InventoryApiClientBase<TvShowDto>(http)
{
    protected override string ApiResourceName => "/api/tv-shows";

    /// <summary>
    /// User-triggered, exact-match-only re-check against the local reference collection
    /// (POST api/tv-shows/{id}/refresh-reference on WebApi). Returns the (possibly now-linked) item so the
    /// caller can tell whether a match was actually found.
    /// </summary>
    public async Task<TvShowDto> RefreshReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TvShowDto>())!;
    }

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document
    /// (POST api/tv-shows/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<TvShowDto> UnlinkReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<TvShowDto>())!;
    }
}
