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

    [SupplyParameterFromQuery(Name = "owned")]
    public bool OwnedFilter { get; set; }

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (FavoriteFilter) query["IsFavorite"] = "true";
            if (OwnedFilter) query["IsOwned"] = "true";
            return query.Count > 0 ? query : null;
        }
    }
}
