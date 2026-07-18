using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class TvShows : InventoryPageBase<TvShowDto>
{
    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    protected override InventoryApiClientBase<TvShowDto> Api => TvShowApi;

    protected override string ListRoute => "/tv-shows";

    [SupplyParameterFromQuery(Name = "state")]
    public string? StateQuery { get; set; }

    [SupplyParameterFromQuery(Name = "favorite")]
    public bool FavoriteFilter { get; set; }

    [SupplyParameterFromQuery(Name = "owned")]
    public bool OwnedFilter { get; set; }

    private TvShowStatus? StateFilter => Enum.TryParse<TvShowStatus>(StateQuery, true, out var state) ? state : null;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (StateFilter is not null) query["State"] = StateFilter.ToString()!;
            if (FavoriteFilter) query["IsFavorite"] = "true";
            if (OwnedFilter) query["IsOwned"] = "true";
            return query.Count > 0 ? query : null;
        }
    }
}
