using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Playlists : InventoryPageBase<PlaylistDto>
{
    [Inject] private PlaylistApiClient PlaylistApi { get; set; } = null!;

    protected override InventoryApiClientBase<PlaylistDto> Api => PlaylistApi;

    protected override string ListRoute => "/playlists";

    protected override PlaylistDto CloneItem(PlaylistDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        SongIds = [.. item.SongIds]
    };
}
