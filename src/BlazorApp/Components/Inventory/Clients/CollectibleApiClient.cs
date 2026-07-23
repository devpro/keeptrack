using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class CollectibleApiClient(HttpClient http)
    : InventoryApiClientBase<CollectibleDto>(http)
{
    protected override string ApiResourceName => "/api/collectibles";
}
