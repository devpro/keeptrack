using KeepTrack.WebApi.Contracts.Dto;

namespace KeepTrack.BlazorApp.Components.Inventory.Clients;

public class VideoGameApiClient(HttpClient http)
    : InventoryApiClientBase<VideoGameDto>(http)
{
    protected override string ApiResourceName => "/api/video-games";
}
