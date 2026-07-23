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

    [SupplyParameterFromQuery(Name = "category")]
    public string? CategoryFilter { get; set; }

    /// <summary>Distinct categories across this tenant's gear, for the Filters row - fetched once, not
    /// tied to search/page/sort state like <see cref="InventoryPageBase{TDto}.Items"/> is.</summary>
    protected List<string> Categories { get; private set; } = [];

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (FavoriteFilter) query["IsFavorite"] = "true";
            if (OwnedFilter) query["IsOwned"] = "true";
            if (!string.IsNullOrEmpty(CategoryFilter)) query["Category"] = CategoryFilter;
            return query.Count > 0 ? query : null;
        }
    }

    protected override async Task OnInitializedAsync()
    {
        await base.OnInitializedAsync();
        Categories = await GearApi.GetCategoriesAsync();
    }
}
