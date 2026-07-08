using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class PlaylistApiClient(HttpClient http)
    : InventoryApiClientBase<PlaylistDto>(http)
{
    protected override string ApiResourceName => "/api/playlists";
}
