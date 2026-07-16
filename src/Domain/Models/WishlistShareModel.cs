namespace Keeptrack.Domain.Models;

/// <summary>
/// One user's wishlist share link: whoever knows <see cref="Token"/> can view that user's current
/// wishlist (a live view, not a snapshot), without an account. The token is a 128-bit random value -
/// unguessable, so the link is private to whoever it was sent to, and deleting the document revokes it.
/// One share per owner: recreating after a revoke issues a fresh token, so old links stay dead.
/// </summary>
public class WishlistShareModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Token { get; set; }
}
