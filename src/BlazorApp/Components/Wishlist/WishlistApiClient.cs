using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Wishlist;

public sealed class WishlistApiClient(HttpClient http)
{
    public async Task<WishlistDto> GetAsync()
    {
        var result = await http.GetFromJsonAsync<WishlistDto>("/api/wishlist");
        return result ?? new WishlistDto();
    }

    /// <summary>Every share link the caller has issued, oldest first.</summary>
    public async Task<List<WishlistShareDto>> GetSharesAsync()
    {
        var result = await http.GetFromJsonAsync<List<WishlistShareDto>>("/api/wishlist/shares");
        return result ?? [];
    }

    public async Task<WishlistShareDto> CreateShareAsync(string? label)
    {
        var response = await http.PostAsJsonAsync("/api/wishlist/shares", new CreateWishlistShareRequestDto { Label = label });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<WishlistShareDto>())!;
    }

    public async Task DeleteShareAsync(string id) =>
        (await http.DeleteAsync($"/api/wishlist/shares/{id}")).EnsureSuccessStatusCode();
}
