using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

public sealed class WishlistApiClient(HttpClient http)
{
    public async Task<WishlistDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<WishlistDto>("/api/wishlist");
        return result ?? new WishlistDto();
    }
}
