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
}
