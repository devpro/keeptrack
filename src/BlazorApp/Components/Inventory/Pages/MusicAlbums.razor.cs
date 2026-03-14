using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class MusicAlbums : InventoryPageBase<MusicAlbumDto>
{
    [Inject] private MusicAlbumApiClient MusicAlbumApi { get; set; } = null!;

    protected override InventoryApiClientBase<MusicAlbumDto> Api => MusicAlbumApi;

    protected override MusicAlbumDto CloneItem(MusicAlbumDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Artist = item.Artist,
        Genre = item.Genre,
        Year = item.Year,
        Rating = item.Rating
    };
}
