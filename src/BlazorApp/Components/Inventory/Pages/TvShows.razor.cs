using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class TvShows : InventoryPageBase<TvShowDto>
{
    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    protected override InventoryApiClientBase<TvShowDto> Api => TvShowApi;

    private TvShowStatus? _statusFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery =>
        _statusFilter is null ? null : new Dictionary<string, string> { ["Status"] = _statusFilter.ToString()! };

    private async Task SetStatusFilterAsync(TvShowStatus? status)
    {
        _statusFilter = status;
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
        Status = item.Status,
        LastEpisodeSeen = item.LastEpisodeSeen,
        Year = item.Year,
        IsFavorite = item.IsFavorite,
        WantToWatch = item.WantToWatch
    };
}
