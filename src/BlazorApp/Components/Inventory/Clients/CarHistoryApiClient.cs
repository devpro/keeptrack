using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class CarHistoryApiClient(HttpClient http)
    : InventoryApiClientBase<CarHistoryDto>(http)
{
    protected override string ApiResourceName => "/api/car-history";

    /// <summary>
    /// Fuel grades already recorded across this tenant's history - see
    /// <c>CarHistoryController.GetFuelCategories</c>.
    /// </summary>
    public async Task<List<string>> GetFuelCategoriesAsync()
    {
        return await Http.GetFromJsonAsync<List<string>>($"{ApiResourceName}/fuel-categories") ?? [];
    }
}
