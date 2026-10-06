using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class SongApiClient(HttpClient http)
    : InventoryApiClientBase<SongDto>(http)
{
    protected override string ApiResourceName => "/api/songs";

    /// <summary>
    /// The shared "add a real track" operation, behind <c>AlbumDetail.razor</c>'s per-track "+ Add to playlist" and <c>PlaylistDetail.razor</c>'s "Add from album" picker.
    /// Picking a track from either place, or twice, reuses one <see cref="SongDto"/> instead of creating a duplicate.
    /// It relies on <c>SongRepository.GetFilter</c>'s exact match on <see cref="SongDto.AlbumId"/> and <see cref="SongDto.TrackPosition"/>, so no dedicated endpoint is needed.
    /// </summary>
    public async Task<SongDto> GetOrCreateForTrackAsync(string albumId, string position, string title, string? duration, string? artist)
    {
        var existing = await GetAsync(search: "",
            page: 1,
            pageSize: 1,
            extraQuery: new Dictionary<string, string>
            {
                ["AlbumId"] = albumId,
                ["TrackPosition"] = position
            });
        if (existing.Items.Count > 0) return existing.Items[0];

        return await AddAsync(new SongDto
        {
            Title = title,
            Artist = artist,
            AlbumId = albumId,
            TrackPosition = position,
            Duration = duration
        });
    }
}
