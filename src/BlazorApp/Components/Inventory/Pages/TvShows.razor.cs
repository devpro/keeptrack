using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class TvShows : InventoryPageBase<TvShowDto>
{
    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    protected override InventoryApiClientBase<TvShowDto> Api => TvShowApi;

    protected override TvShowDto CloneItem(TvShowDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Rating = item.Rating,
        AllocineId = item.AllocineId,
        ImdbPageId = item.ImdbPageId,
        Notes = item.Notes,
        FinishedAt = item.FinishedAt,
        LastEpisodeSeen = item.LastEpisodeSeen,
        Year = item.Year
    };
}
