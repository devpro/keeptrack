using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class HouseApiClient(HttpClient http)
    : InventoryApiClientBase<HouseDto>(http)
{
    protected override string ApiResourceName => "/api/houses";

    public async Task<HouseMetricsDto> GetMetricsAsync(string id)
    {
        var result = await Http.GetFromJsonAsync<HouseMetricsDto>($"{ApiResourceName}/{id}/metrics");
        return result!;
    }
}
