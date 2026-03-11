using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class VideoGameApiClient(HttpClient http)
    : InventoryApiClientBase<VideoGameDto>(http)
{
    protected override string ApiResourceName => "/api/video-games";
}
