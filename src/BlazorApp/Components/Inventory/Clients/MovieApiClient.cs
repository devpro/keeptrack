using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class MovieApiClient(HttpClient http)
    : InventoryApiClientBase<MovieDto>(http, hasReference: true)
{
    protected override string ApiResourceName => "/api/movies";
}
