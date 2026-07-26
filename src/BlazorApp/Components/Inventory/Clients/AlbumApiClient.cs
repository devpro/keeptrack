using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class AlbumApiClient(HttpClient http)
    : InventoryApiClientBase<AlbumDto>(http, hasReference: true)
{
    protected override string ApiResourceName => "/api/albums";
}
