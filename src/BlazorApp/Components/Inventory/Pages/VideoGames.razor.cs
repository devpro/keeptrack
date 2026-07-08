using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class VideoGames : InventoryPageBase<VideoGameDto>
{
    /// <summary>Shared by the list's Filters buttons and the Add/Edit forms' State button group.</summary>
    internal static readonly string[] VideoGameStates = ["Available", "Current", "Completed", "To resume", "On-hold"];

    /// <summary>
    /// The <c>kt-status-badge</c> modifier class for a state value (see app.css) - same badge/color
    /// pattern as <c>TvShows.razor</c>'s status column, sharing its "current" modifier for the identical
    /// in-progress meaning and adding the three states with no TV show equivalent.
    /// </summary>
    internal static string StateBadgeClass(string state) => state.ToLowerInvariant().Replace(" ", "-");

    [Inject] private VideoGameApiClient VideoGameApi { get; set; } = null!;

    protected override InventoryApiClientBase<VideoGameDto> Api => VideoGameApi;

    private string? _stateFilter;

    private bool _ownedFilter;

    private bool _wishlistedFilter;

    protected override IReadOnlyDictionary<string, string>? ExtraQuery
    {
        get
        {
            var query = new Dictionary<string, string>();
            if (!string.IsNullOrEmpty(_stateFilter)) query["State"] = _stateFilter;
            if (_ownedFilter) query["IsOwned"] = "true";
            if (_wishlistedFilter) query["IsWishlisted"] = "true";
            return query.Count > 0 ? query : null;
        }
    }

    private async Task SetStateFilterAsync(string? state)
    {
        _stateFilter = state;
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

    protected override VideoGameDto CloneItem(VideoGameDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        Platform = item.Platform,
        State = item.State,
        FinishedAt = item.FinishedAt,
        Notes = item.Notes,
        Rating = item.Rating,
        Year = item.Year,
        ReferenceId = item.ReferenceId,
        IsOwned = item.IsOwned,
        IsWishlisted = item.IsWishlisted
    };
}
