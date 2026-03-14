using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Movies : InventoryPageBase<MovieDto>
{
    [Inject] private MovieApiClient MovieApi { get; set; } = null!;

    protected override InventoryApiClientBase<MovieDto> Api => MovieApi;

    protected override MovieDto CloneItem(MovieDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Year = item.Year,
        Genre = item.Genre,
        Rating = item.Rating,
        Notes = item.Notes,
        FirstSeenAt = item.FirstSeenAt,
        AllocineId = item.AllocineId,
        ImdbPageId = item.ImdbPageId
    };
}
