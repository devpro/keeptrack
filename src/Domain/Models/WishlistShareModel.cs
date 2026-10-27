using System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One wishlist share link: whoever knows <see cref="Token"/> sees the owner's current wishlist, live rather than a snapshot, without an account.
/// The token is a random 128-bit value, so the link is private to whoever received it, and deleting the document revokes that link only.
/// An owner can hold several, each with its own <see cref="Label"/> ("Mum", "Gift exchange"), so one leaked link is revoked without the others.
/// </summary>
public class WishlistShareModel
{
    public string? Id { get; set; }

    public required string OwnerId { get; set; }

    public required string Token { get; set; }

    /// <summary>Free text for the owner's own bookkeeping, such as who got this link, never shown to recipients.</summary>
    public string? Label { get; set; }

    /// <summary>Stamped by the repository at creation, and shown in the owner's list of shares.</summary>
    public DateTime CreatedAt { get; set; }
}
