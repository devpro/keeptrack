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
        ReferenceId = item.ReferenceId,
        Notes = item.Notes,
        FinishedAt = item.FinishedAt,
        LastEpisodeSeen = item.LastEpisodeSeen,
        Year = item.Year,
        IsFavorite = item.IsFavorite,
        WantToWatch = item.WantToWatch
    };
}
