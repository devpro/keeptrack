using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class TvShows : InventoryPageBase<TvShowDto>
{
    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    protected override InventoryApiClientBase<TvShowDto> Api => TvShowApi;

    private TvShowStatus? _stateFilter;

    private bool _favoriteFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (_stateFilter is not null) query["State"] = _stateFilter.ToString()!;
            if (_favoriteFilter) query["IsFavorite"] = "true";
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
        WantToWatch = item.WantToWatch
    };
}
