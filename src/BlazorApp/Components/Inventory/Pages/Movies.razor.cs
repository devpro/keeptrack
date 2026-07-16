using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Movies : InventoryPageBase<MovieDto>
{
    [Inject] private MovieApiClient MovieApi { get; set; } = null!;

    protected override InventoryApiClientBase<MovieDto> Api => MovieApi;

    protected override string ListRoute => "/movies";

    [SupplyParameterFromQuery(Name = "favorite")]
    public bool FavoriteFilter { get; set; }

    [SupplyParameterFromQuery(Name = "owned")]
    public bool OwnedFilter { get; set; }

    [SupplyParameterFromQuery(Name = "wishlisted")]
    public bool WishlistedFilter { get; set; }

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (FavoriteFilter) query["IsFavorite"] = "true";
            if (OwnedFilter) query["IsOwned"] = "true";
            if (WishlistedFilter) query["IsWishlisted"] = "true";
            return query.Count > 0 ? query : null;
        }
    }
}
