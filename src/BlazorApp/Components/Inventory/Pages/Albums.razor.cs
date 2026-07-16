using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Albums : InventoryPageBase<AlbumDto>
{
    [Inject] private AlbumApiClient AlbumApi { get; set; } = null!;

    protected override InventoryApiClientBase<AlbumDto> Api => AlbumApi;

    protected override string ListRoute => "/albums";

    [SupplyParameterFromQuery(Name = "favorite")]
    public bool FavoriteFilter { get; set; }

    protected override IReadOnlyDictionary<string, string>? ExtraQuery =>
        FavoriteFilter ? new Dictionary<string, string> { ["IsFavorite"] = "true" } : null;
}
