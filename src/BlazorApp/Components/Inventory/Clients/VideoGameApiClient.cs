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

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document
    /// (POST api/video-games/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<VideoGameDto> UnlinkReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VideoGameDto>())!;
    }
}
