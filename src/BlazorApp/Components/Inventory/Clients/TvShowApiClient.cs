using KeepTrack.WebApi.Contracts.Dto;

namespace KeepTrack.BlazorApp.Components.Inventory.Clients;

public class TvShowApiClient(HttpClient http)
    : InventoryApiClientBase<TvShowDto>(http)
{
    protected override string ApiResourceName => "/api/tv-shows";
}
