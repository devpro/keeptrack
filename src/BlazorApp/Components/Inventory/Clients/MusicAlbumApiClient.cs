using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class MusicAlbumApiClient(HttpClient http)
    : InventoryApiClientBase<MusicAlbumDto>(http)
{
    protected override string ApiResourceName => "/api/movies";
}
