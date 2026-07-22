using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class GearApiClient(HttpClient http)
    : InventoryApiClientBase<GearDto>(http)
{
    protected override string ApiResourceName => "/api/gear";
}
