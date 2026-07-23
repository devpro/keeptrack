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

    /// <summary>
    /// Admin-only: unlinks and permanently deletes the shared reference document
    /// (POST api/books/{id}/unlink-reference on WebApi).
    /// </summary>
    public async Task<BookDto> UnlinkReferenceAsync(string id)
    {
        var response = await Http.PostAsync($"{ApiResourceName}/{id}/unlink-reference", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BookDto>())!;
    }
}
