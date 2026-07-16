namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The caller's wishlist share link. Anyone who knows the token can view the wishlist (live, read-only,
/// no account needed) at <c>/shared/wishlist/{token}</c>; deleting the share revokes every copy of the link.
/// </summary>
public class WishlistShareDto
{
    /// <summary>The unguessable 128-bit token identifying this share.</summary>
    public required string Token { get; set; }
}
