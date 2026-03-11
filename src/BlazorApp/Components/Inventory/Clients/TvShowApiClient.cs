using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public class TvShowApiClient(HttpClient http)
    : InventoryApiClientBase<TvShowDto>(http)
{
    protected override string ApiResourceName => "/api/tv-shows";
}
