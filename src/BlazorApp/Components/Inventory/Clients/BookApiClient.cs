using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class BookApiClient(HttpClient http)
    : InventoryApiClientBase<BookDto>(http)
{
    protected override string ApiResourceName => "/api/books";
}
