using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One directed share grant: the owner (<see cref="OwnerId"/>) lets the account whose email is <see cref="RecipientEmail"/> view whole categories of their collection, read-only.
/// Unlike the anonymous wishlist link (<see cref="WishlistShareModel"/>), access goes to a named account, not a token in a URL.
/// The recipient is matched server side by their authenticated email on every read.
/// An owner holds one grant per person, each revocable on its own.
/// </summary>
public class ShareModel : IHasId
{
    public string? Id { get; set; }

    /// <summary>The sharer, whose collection this grant exposes.</summary>
    public required string OwnerId { get; set; }

    /// <summary>
    /// Copied at creation from the sharer's display name or email claim, so the recipient's "shared with me" list names the sharer without a user directory.
    /// </summary>
    public string? OwnerDisplayName { get; set; }

    /// <summary>The recipient's account email, normalized lowercase, which is the grant's access key.</summary>
    public required string RecipientEmail { get; set; }

    /// <summary>The categories this grant exposes, never individual items.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];

    /// <summary>Free text for the owner's own bookkeeping ("Mum", "Dad"), never shown to the recipient.</summary>
    public string? Label { get; set; }

    /// <summary>Stamped by the repository at creation, and shown in the owner's list of shares.</summary>
    public DateTime CreatedAt { get; set; }
}
