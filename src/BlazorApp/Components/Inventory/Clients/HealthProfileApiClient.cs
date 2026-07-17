using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class HealthProfileApiClient(HttpClient http)
    : InventoryApiClientBase<HealthProfileDto>(http)
{
    protected override string ApiResourceName => "/api/health-profiles";

    public async Task<HealthMetricsDto> GetMetricsAsync(string id)
    {
        var result = await Http.GetFromJsonAsync<HealthMetricsDto>($"{ApiResourceName}/{id}/metrics");
        return result!;
    }
}
