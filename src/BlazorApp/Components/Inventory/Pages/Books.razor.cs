using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Books : InventoryPageBase<BookDto>
{
    [Inject] private BookApiClient BookApi { get; set; } = null!;

    protected override InventoryApiClientBase<BookDto> Api => BookApi;

    private bool _favoriteFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery =>
        _favoriteFilter ? new Dictionary<string, string> { ["IsFavorite"] = "true" } : null;

    private async Task ToggleFavoriteFilterAsync()
    {
        _favoriteFilter = !_favoriteFilter;
        _page = 1;
        await LoadAsync();
    }

    protected override BookDto CloneItem(BookDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Author = item.Author,
        Series = item.Series,
        Year = item.Year,
        Genre = item.Genre,
        Rating = item.Rating,
        Notes = item.Notes,
        FirstReadAt = item.FirstReadAt,
        ReferenceId = item.ReferenceId,
        IsFavorite = item.IsFavorite
    };
}
