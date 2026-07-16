using System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One of the caller's wishlist share links. Anyone who knows the token can view the wishlist (live,
/// read-only, no account needed) at <c>/shared/wishlist/{token}</c>; deleting the share revokes every
/// copy of that one link without touching the caller's other shares.
/// </summary>
public class WishlistShareDto
{
    /// <summary>The share's own id - what <c>DELETE /api/wishlist/shares/{id}</c> revokes.</summary>
    public required string Id { get; set; }

    /// <summary>The unguessable 128-bit token identifying this share.</summary>
    public required string Token { get; set; }

    /// <summary>The owner's own label for this link (who it was sent to) - never shown to recipients.</summary>
    public string? Label { get; set; }

    /// <summary>When the share was created (UTC).</summary>
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Request body for creating a wishlist share link.
/// </summary>
public class CreateWishlistShareRequestDto
{
    /// <summary>Optional label for the owner's own bookkeeping (who this link is for).</summary>
    public string? Label { get; set; }
}
