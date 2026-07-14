using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class VideoGameApiClient(HttpClient http)
    : InventoryApiClientBase<VideoGameDto>(http)
{
    protected override string ApiResourceName => "/api/video-games";

    public async Task<VideoGameDto> RefreshReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VideoGameDto>())!;
    }
}
