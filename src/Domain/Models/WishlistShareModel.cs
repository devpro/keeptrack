using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One wishlist share link: whoever knows <see cref="Token"/> can view the owner's current wishlist
/// (a live view, not a snapshot), without an account. The token is a 128-bit random value -
/// unguessable, so the link is private to whoever it was sent to, and deleting the document revokes
/// that link (and only it). An owner can hold several at once, each with its own <see cref="Label"/>
/// ("Mum", "Gift exchange"), so a single leaked or stale link can be revoked without killing the rest.
/// </summary>
public class WishlistShareModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Token { get; set; }

    /// <summary>Free text for the owner's own bookkeeping (who got this link) - never shown to recipients.</summary>
    public string? Label { get; set; }

    /// <summary>Stamped by the repository at creation; carried back on reads for the owner's share list.</summary>
    public DateTime CreatedAt { get; set; }
}
