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
    /// Whether the caller holds a membership (or is an admin, which always implies one) - the same
    /// role values the "MemberOnly" policy accepts, for code paths that adjust behavior instead of
    /// denying access outright (the free-tier creation quota).
    /// </summary>
    internal static bool IsMember(this ControllerBase controller) =>
        controller.User.HasClaim("role", "member") || controller.User.HasClaim("role", "admin");
}
