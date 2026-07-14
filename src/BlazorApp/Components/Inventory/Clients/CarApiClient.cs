using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class CarApiClient(HttpClient http)
    : InventoryApiClientBase<CarDto>(http)
{
    protected override string ApiResourceName => "/api/cars";

    public async Task<CarMetricsDto> GetMetricsAsync(string id)
    {
        var result = await Http.GetFromJsonAsync<CarMetricsDto>($"{ApiResourceName}/{id}/metrics");
        return result!;
    }
}
