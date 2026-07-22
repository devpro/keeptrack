using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Gear : InventoryPageBase<GearDto>
{
    [Inject] private GearApiClient GearApi { get; set; } = null!;

    protected override InventoryApiClientBase<GearDto> Api => GearApi;

    protected override string ListRoute => "/gear";

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
