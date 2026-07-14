using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class EpisodeApiClient(HttpClient http)
    : InventoryApiClientBase<EpisodeDto>(http)
{
    protected override string ApiResourceName => "/api/episodes";
}
