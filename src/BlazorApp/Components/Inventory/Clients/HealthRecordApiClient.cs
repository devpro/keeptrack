using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class HealthRecordApiClient(HttpClient http)
    : InventoryApiClientBase<HealthRecordDto>(http)
{
    protected override string ApiResourceName => "/api/health-records";

    /// <summary>
    /// Specialties and practitioners already recorded by this account, feeding the journal form's
    /// suggestion dropdowns - see <c>HealthRecordController.GetSuggestions</c>. One call for both lists,
    /// since the form opens needing both.
    /// </summary>
    public async Task<HealthRecordSuggestionsDto> GetSuggestionsAsync()
    {
        return await Http.GetFromJsonAsync<HealthRecordSuggestionsDto>($"{ApiResourceName}/suggestions") ?? new HealthRecordSuggestionsDto();
    }
}
