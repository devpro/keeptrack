using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class BookApiClient(HttpClient http)
    : InventoryApiClientBase<BookDto>(http)
{
    protected override string ApiResourceName => "/api/books";

    public async Task<BookDto> RefreshReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/refresh-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BookDto>())!;
    }
}
