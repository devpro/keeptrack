using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class CarHistoryApiClient(HttpClient http)
    : InventoryApiClientBase<CarHistoryDto>(http)
{
    protected override string ApiResourceName => "/api/car-history";
}
