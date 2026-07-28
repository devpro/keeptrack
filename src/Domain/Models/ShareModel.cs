using System;
using System.Collections.Generic;
using Keeptrack.Common.System;

namespace Keeptrack.Domain.Models;

/// <summary>
/// One directed share grant: the owner (<see cref="OwnerId"/>) lets the account whose email is
/// <see cref="RecipientEmail"/> view whole categories of their collection, read-only. Unlike the
/// anonymous wishlist link (<see cref="WishlistShareModel"/>), access is a named account, not a token in
/// a URL - the recipient is matched server-side by their authenticated email on every read. An owner
/// holds several grants at once (one per person), each independently revocable.
/// </summary>
public class ShareModel : IHasId
{
    public string? Id { get; set; }

    /// <summary>The sharer - whose collection this grant exposes.</summary>
    public required string OwnerId { get; set; }

    /// <summary>
    /// Denormalized at creation from the sharer's own display name/email claim, so the recipient's
    /// "shared with me" list can name who shared without a user-directory lookup.
    /// </summary>
    public string? OwnerDisplayName { get; set; }

    /// <summary>The recipient's account email, normalized lowercase - the grant's access key.</summary>
    public required string RecipientEmail { get; set; }

    /// <summary>The categories this grant exposes. Category-level by design; never per-item.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];

    /// <summary>Free text for the owner's own bookkeeping ("Mum", "Dad") - never shown to the recipient.</summary>
    public string? Label { get; set; }

    /// <summary>Stamped by the repository at creation; carried back on reads for the owner's share list.</summary>
    public DateTime CreatedAt { get; set; }
}
