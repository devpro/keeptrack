using KeepTrack.WebApi.Contracts.Dto;

namespace KeepTrack.BlazorApp.Components.Inventory.Clients;

public sealed class MoviesApiClient(HttpClient http)
    : InventoryApiClientBase<MovieDto>(http)
{
    protected override string ApiResourceName => "/api/movies";
}
