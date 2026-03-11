using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class VideoGames : InventoryPageBase<VideoGameDto>
{
    [Inject] private VideoGameApiClient VideoGameApi { get; set; } = null!;

    protected override InventoryApiClientBase<VideoGameDto> Api => VideoGameApi;

    protected override VideoGameDto CloneItem(VideoGameDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Platform = item.Platform,
        ReleasedAt = item.ReleasedAt,
        State = item.State,
        FinishedAt = item.FinishedAt
    };
}
