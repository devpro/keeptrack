using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

internal static class ControllerBaseExtensions
{
    internal static string GetUserId(this ControllerBase controller)
    {
        var userId = controller.User.Claims.FirstOrDefault(x => x.Type == "user_id")?.Value;
        return string.IsNullOrEmpty(userId) ? throw new UnauthorizedAccessException() : userId;
    }

    /// <summary>
    /// The caller's account email, normalized lowercase, or null when the token has none: the key matching share grants addressed to them.
    /// <c>MapInboundClaims = false</c> (Program.cs) keeps the Firebase <c>email</c> claim's name.
    /// Nullable, since a provider can yield no email (a GitHub account with a private email), and such a user cannot receive a share.
    /// </summary>
    internal static string? GetEmail(this ControllerBase controller)
    {
        var email = controller.User.Claims.FirstOrDefault(x => x.Type == "email")?.Value;
        return string.IsNullOrEmpty(email) ? null : email.Trim().ToLowerInvariant();
    }

    /// <summary>The caller's display name, or null when the token has none, copied onto a share grant.</summary>
    internal static string? GetDisplayName(this ControllerBase controller) =>
        controller.User.Claims.FirstOrDefault(x => x.Type == "name")?.Value;

    /// <summary>
    /// Whether the caller is a member or an admin, the roles the "MemberOnly" policy accepts, for code that adjusts behavior rather than denying access (the free-tier quota).
    /// </summary>
    internal static bool IsMember(this ControllerBase controller) =>
        controller.User.HasClaim("role", "member") || controller.User.HasClaim("role", "admin");
}
