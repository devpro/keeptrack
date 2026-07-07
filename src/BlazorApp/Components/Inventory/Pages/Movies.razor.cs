using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Movies : InventoryPageBase<MovieDto>
{
    [Inject] private MovieApiClient MovieApi { get; set; } = null!;

    protected override InventoryApiClientBase<MovieDto> Api => MovieApi;

    private bool _favoriteFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery =>
        _favoriteFilter ? new Dictionary<string, string> { ["IsFavorite"] = "true" } : null;

    private async Task ToggleFavoriteFilterAsync()
    {
        _favoriteFilter = !_favoriteFilter;
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
        WantToWatch = item.WantToWatch
    };
}
