using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class GearApiClient(HttpClient http)
    : InventoryApiClientBase<GearDto>(http)
{
    protected override string ApiResourceName => "/api/gear";

    /// <summary>Distinct categories already used across this tenant's gear - see <c>GearController.GetCategories</c>.</summary>
    public async Task<List<string>> GetCategoriesAsync() =>
        await Http.GetFromJsonAsync<List<string>>($"{ApiResourceName}/categories") ?? [];
}
