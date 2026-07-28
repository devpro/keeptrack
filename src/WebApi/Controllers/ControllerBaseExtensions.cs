using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

internal static class ControllerBaseExtensions
{
    /// <summary>
    /// Get authenticated user id.
    /// </summary>
    internal static string GetUserId(this ControllerBase controller)
    {
        var userId = controller.User.Claims.FirstOrDefault(x => x.Type == "user_id")?.Value;
        return string.IsNullOrEmpty(userId) ? throw new UnauthorizedAccessException() : userId;
    }

    /// <summary>
    /// The caller's account email, normalized lowercase, or null when the token carries none - the key
    /// that matches share grants addressed to them. Read verbatim because WebApi sets
    /// <c>MapInboundClaims = false</c> (see Program.cs), so the Firebase <c>email</c> claim keeps its own
    /// name. Nullable (unlike <see cref="GetUserId"/>): a provider can legitimately yield no email (e.g. a
    /// GitHub account with a private email), and such a user simply can't be a share recipient.
    /// </summary>
    internal static string? GetEmail(this ControllerBase controller)
    {
        var email = controller.User.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
        return string.IsNullOrEmpty(email) ? null : email.Trim().ToLowerInvariant();
    }

    /// <summary>The caller's display name, or null when the token carries none - denormalized onto a share grant.</summary>
    internal static string? GetDisplayName(this ControllerBase controller) =>
        controller.User.Claims.FirstOrDefault(x => x.Type == "name")?.Value;

    /// <summary>
    /// Whether the caller holds a membership (or is an admin, which always implies one) - the same
    /// role values the "MemberOnly" policy accepts, for code paths that adjust behavior instead of
    /// denying access outright (the free-tier creation quota).
    /// </summary>
    internal static bool IsMember(this ControllerBase controller) =>
        controller.User.HasClaim("role", "member") || controller.User.HasClaim("role", "admin");
}
