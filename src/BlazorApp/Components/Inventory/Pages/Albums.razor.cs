using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Albums : InventoryPageBase<AlbumDto>
{
    [Inject] private AlbumApiClient AlbumApi { get; set; } = null!;

    protected override InventoryApiClientBase<AlbumDto> Api => AlbumApi;

    private bool _favoriteFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery =>
        _favoriteFilter ? new Dictionary<string, string> { ["IsFavorite"] = "true" } : null;

    private async Task ToggleFavoriteFilterAsync()
    {
        _favoriteFilter = !_favoriteFilter;
        _page = 1;
        await LoadAsync();
    }

    protected override AlbumDto CloneItem(AlbumDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Artist = item.Artist,
        Genre = item.Genre,
        Year = item.Year,
        Rating = item.Rating,
        ReferenceId = item.ReferenceId,
        IsFavorite = item.IsFavorite
    };
}
