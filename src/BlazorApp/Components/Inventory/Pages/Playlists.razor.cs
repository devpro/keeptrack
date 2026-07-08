using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.Inventory.Pages;

public partial class Playlists : InventoryPageBase<PlaylistDto>
{
    [Inject] private PlaylistApiClient PlaylistApi { get; set; } = null!;

    [Inject] private NavigationManager Nav { get; set; } = null!;

    protected override InventoryApiClientBase<PlaylistDto> Api => PlaylistApi;

    /// <summary>
    /// Creating a playlist only ever captures Title here (see <c>FormTemplate</c>) - songs are added on
    /// the detail page, so a successful create navigates straight there instead of closing the form and
    /// staying on the list. Same rationale as <c>VideoGames.razor.cs</c>'s override.
    /// </summary>
    protected override async Task SaveAsync()
    {
        try
        {
            if (_form.Id is null)
            {
                var created = await PlaylistApi.AddAsync(_form);
                _showForm = false;
                Nav.NavigateTo($"/playlists/{created.Id}");
            }
            else
            {
                await PlaylistApi.UpdateAsync(_form);
                _showForm = false;
                await LoadAsync();
            }
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
    }

    protected override PlaylistDto CloneItem(PlaylistDto item) => new()
    {
        Id = item.Id,
        Title = item.Title,
        SongIds = [.. item.SongIds]
    };
}
