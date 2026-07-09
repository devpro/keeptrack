using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class HouseHistoryApiClient(HttpClient http)
    : InventoryApiClientBase<HouseHistoryDto>(http)
{
    protected override string ApiResourceName => "/api/house-history";
}
