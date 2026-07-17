using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class HealthRecordApiClient(HttpClient http)
    : InventoryApiClientBase<HealthRecordDto>(http)
{
    protected override string ApiResourceName => "/api/health-records";
}
