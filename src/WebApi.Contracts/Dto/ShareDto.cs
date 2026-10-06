using System;
using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One share grant the caller issued: the account with <see cref="RecipientEmail"/> can view the listed categories of the caller's collection, read-only.
/// Deleting it (<c>DELETE /api/shares/{id}</c>) revokes that recipient's access only.
/// </summary>
public class ShareDto
{
    /// <summary>The grant's id, which <c>DELETE /api/shares/{id}</c> revokes.</summary>
    public required string Id { get; set; }

    /// <summary>The recipient's account email (normalized lowercase).</summary>
    public required string RecipientEmail { get; set; }

    /// <summary>The categories this grant exposes.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];

    /// <summary>The caller's own label for this grant, such as who it is for, never shown to the recipient.</summary>
    public string? Label { get; set; }

    /// <summary>When the grant was created (UTC).</summary>
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Request body for creating a share grant.
/// </summary>
public class CreateShareRequestDto
{
    /// <summary>The recipient's account email, the address they sign in with.</summary>
    public required string RecipientEmail { get; set; }

    /// <summary>The categories to share, at least one, the personal ones only when chosen.</summary>
    public List<ShareCategory> IncludedCategories { get; set; } = [];

    /// <summary>Optional label for the caller's own bookkeeping, such as who the grant is for.</summary>
    public string? Label { get; set; }
}
