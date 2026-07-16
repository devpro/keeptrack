using System.Net;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

public sealed class WishlistApiClient(HttpClient http)
{
    public async Task<WishlistDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<WishlistDto>("/api/wishlist");
        return result ?? new WishlistDto();
    }

    /// <summary>The caller's active share link, or null when the wishlist isn't shared.</summary>
    public async Task<WishlistShareDto?> GetShareAsync()
    {
        var response = await http.GetAsync("/api/wishlist/share");
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<WishlistShareDto>();
    }

    public async Task<WishlistShareDto> CreateShareAsync()
    {
        var response = await http.PostAsync("/api/wishlist/share", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<WishlistShareDto>())!;
    }

    public async Task DeleteShareAsync() =>
        (await http.DeleteAsync("/api/wishlist/share")).EnsureSuccessStatusCode();
}
