using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Movies : InventoryPageBase<MovieDto>
{
    [Inject] private MovieApiClient MovieApi { get; set; } = null!;

    protected override InventoryApiClientBase<MovieDto> Api => MovieApi;

    protected override string ListRoute => "/movies";

    private bool _favoriteFilter;

    private bool _ownedFilter;

    private bool _wishlistedFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (_favoriteFilter) query["IsFavorite"] = "true";
            if (_ownedFilter) query["IsOwned"] = "true";
            if (_wishlistedFilter) query["IsWishlisted"] = "true";
            return query.Count > 0 ? query : null;
        }
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

    protected override MovieDto CloneItem(MovieDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Year = item.Year,
        Rating = item.Rating,
        Notes = item.Notes,
        FirstSeenAt = item.FirstSeenAt,
        ReferenceId = item.ReferenceId,
        IsFavorite = item.IsFavorite,
        WantToWatch = item.WantToWatch,
        IsOwned = item.IsOwned,
        IsWishlisted = item.IsWishlisted
    };
}
