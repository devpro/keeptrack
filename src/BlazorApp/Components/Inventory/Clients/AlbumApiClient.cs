using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class AlbumApiClient(HttpClient http)
    : InventoryApiClientBase<AlbumDto>(http)
{
    protected override string ApiResourceName => "/api/albums";

    public async Task<AlbumDto> RefreshReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AlbumDto>())!;
    }

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document
    /// (POST api/albums/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<AlbumDto> UnlinkReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AlbumDto>())!;
    }
}
