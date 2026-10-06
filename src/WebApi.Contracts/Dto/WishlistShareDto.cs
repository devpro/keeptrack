using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One of the caller's wishlist share links.
/// Anyone who knows the token sees the wishlist, live and read-only with no account, at <c>/shared/wishlist/{token}</c>.
/// Deleting the share revokes that link only.
/// </summary>
public class WishlistShareDto
{
    /// <summary>The share's id, which <c>DELETE /api/wishlist/shares/{id}</c> revokes.</summary>
    public required string Id { get; set; }

    /// <summary>The unguessable 128-bit token identifying this share.</summary>
    public required string Token { get; set; }

    /// <summary>The owner's own label for this link, such as who it was sent to, never shown to recipients.</summary>
    public string? Label { get; set; }

    /// <summary>When the share was created (UTC).</summary>
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Request body for creating a wishlist share link.
/// </summary>
public class CreateWishlistShareRequestDto
{
    /// <summary>Optional label for the owner's own bookkeeping, such as who the link is for.</summary>
    public string? Label { get; set; }
}
