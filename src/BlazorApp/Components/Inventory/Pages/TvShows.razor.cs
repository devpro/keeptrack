using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class TvShows : InventoryPageBase<TvShowDto>
{
    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    protected override InventoryApiClientBase<TvShowDto> Api => TvShowApi;

    private TvShowStatus? _stateFilter;

    private bool _favoriteFilter;

    private bool _ownedFilter;

    private bool _wishlistedFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (_stateFilter is not null) query["State"] = _stateFilter.ToString()!;
            if (_favoriteFilter) query["IsFavorite"] = "true";
            if (_ownedFilter) query["IsOwned"] = "true";
            if (_wishlistedFilter) query["IsWishlisted"] = "true";
            return query.Count > 0 ? query : null;
        }
    }

    private async Task SetStateFilterAsync(TvShowStatus? state)
    {
        _stateFilter = state;
        _page = 1;
        await LoadAsync();
    }

    private async Task ToggleFavoriteFilterAsync()
    {
        _favoriteFilter = !_favoriteFilter;
        _page = 1;
        await LoadAsync();
    }

    private async Task ToggleOwnedFilterAsync()
    {
        _ownedFilter = !_ownedFilter;
        _page = 1;
        await LoadAsync();
    }

    private async Task ToggleWishlistedFilterAsync()
    {
        _wishlistedFilter = !_wishlistedFilter;
        _page = 1;
        await LoadAsync();
    }

    protected override TvShowDto CloneItem(TvShowDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Rating = item.Rating,
        ReferenceId = item.ReferenceId,
        Notes = item.Notes,
        State = item.State,
        LastEpisodeSeen = item.LastEpisodeSeen,
        Year = item.Year,
        IsFavorite = item.IsFavorite,
        WantToWatch = item.WantToWatch,
        IsOwned = item.IsOwned,
        IsWishlisted = item.IsWishlisted
    };
}
