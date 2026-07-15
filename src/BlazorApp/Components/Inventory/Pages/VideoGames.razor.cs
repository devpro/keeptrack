using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class VideoGames : InventoryPageBase<VideoGameDto>
{
    /// <summary>Shared by the list's Filters buttons, the detail page's per-platform State buttons, and
    /// the (now-removed from the list page) Add/Edit forms' old State button group.</summary>
    internal static readonly string[] VideoGameStates = ["Available", "Current", "Completed", "To resume", "On-hold"];

    /// <summary>Shared by the detail page's platform picker - previously duplicated as a literal
    /// &lt;select&gt; in three places (list add form, list edit modal, detail page).</summary>
    internal static readonly string[] VideoGamePlatforms =
        ["Xbox Series X", "PS5", "PC", "Xbox One X", "PS4", "WII", "Xbox 360", "PS2", "PS1"];

    /// <summary>
    /// The <c>kt-status-badge</c> modifier class for a state value (see app.css) - same badge/color
    /// pattern as <c>TvShows.razor</c>'s status column, sharing its "current" modifier for the identical
    /// in-progress meaning and adding the three states with no TV show equivalent.
    /// </summary>
    internal static string StateBadgeClass(string state) => state.ToLowerInvariant().Replace(" ", "-");

    [Inject] private VideoGameApiClient VideoGameApi { get; set; } = null!;

    protected override InventoryApiClientBase<VideoGameDto> Api => VideoGameApi;

    protected override string ListRoute => "/video-games";

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

}
