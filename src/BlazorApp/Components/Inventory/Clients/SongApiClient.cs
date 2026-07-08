using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Inventory.Clients;

public sealed class SongApiClient(HttpClient http)
    : InventoryApiClientBase<SongDto>(http)
{
    protected override string ApiResourceName => "/api/songs";

    /// <summary>
    /// The single shared "add a real track" operation - reused by both <c>AlbumDetail.razor</c>'s
    /// per-track "+ Add to playlist" and <c>PlaylistDetail.razor</c>'s "Add from album" picker, so picking
    /// the same track from two different places (or twice from the same place) reuses one <see cref="SongDto"/>
    /// instead of creating a duplicate. Relies on <c>SongRepository.GetFilter</c>'s exact-match on
    /// <see cref="SongDto.AlbumId"/>/<see cref="SongDto.TrackPosition"/> - no dedicated WebApi endpoint needed.
    /// </summary>
    public async Task<SongDto> GetOrCreateForTrackAsync(string albumId, string position, string title, string? duration, string? artist)
    {
        var existing = await GetAsync("", 1, 1, new Dictionary<string, string> { ["AlbumId"] = albumId, ["TrackPosition"] = position });
        if (existing.Items.Count > 0) return existing.Items[0];

        return await AddAsync(new SongDto { Title = title, Artist = artist, AlbumId = albumId, TrackPosition = position, Duration = duration });
    }
}
