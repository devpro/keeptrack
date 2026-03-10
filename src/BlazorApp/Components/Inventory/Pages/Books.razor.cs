using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Books : InventoryPageBase<BookDto>
{
    [Inject] private BookApiClient BookApi { get; set; } = null!;

    protected override InventoryApiClientBase<BookDto> Api => BookApi;

    protected override BookDto CloneItem(BookDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Author = item.Author,
        FinishedAt = item.FinishedAt,
        Series = item.Series
    };
}
