using System.Net;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

/// <summary>
/// Fetches a shared wishlist by token, the app's one anonymous API read.
/// It is registered without <c>AuthenticationTokenHandler</c>, which would bounce an anonymous visitor to the login page.
/// </summary>
public sealed class SharedWishlistApiClient(HttpClient http)
{
    /// <summary>
    /// Null when the token is unknown or the share was revoked.
    /// </summary>
    public async Task<WishlistDto?> GetAsync(string token)
    {
        var response = await http.GetAsync($"/api/wishlist/shared/{Uri.EscapeDataString(token)}");
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<WishlistDto>();
    }
}
