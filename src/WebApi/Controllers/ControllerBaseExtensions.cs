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
}
