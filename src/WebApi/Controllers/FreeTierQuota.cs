using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The free preview creation quota, written once so every creation path enforces it: the CRUD create (<see cref="DataCrudControllerBase{TDto, TModel}.Post"/>), the shared item copy (<see cref="SharedWithMeController"/>) and Explore's add.
/// Enforced server side, since hiding UI is not security.
/// Members and admins are never counted.
/// </summary>
internal static class FreeTierQuota
{
    /// <summary>
    /// An error message to show when the caller is over the free-tier limit for this collection, or null when the creation may proceed.
    /// <paramref name="limitFactor"/> is 0 for member-only collections, gated separately, and otherwise a multiple of <c>Features:FreeTierItemLimit</c>.
    /// </summary>
    internal static async Task<string?> CheckAsync(ControllerBase controller, int limitFactor, Func<Task<long>> countAsync)
    {
        if (limitFactor <= 0 || controller.IsMember())
        {
            return null;
        }

        var configuration = controller.HttpContext.RequestServices.GetRequiredService<IConfiguration>();
        var limit = AppConfiguration.GetFreeTierItemLimit(configuration) * limitFactor;
        if (await countAsync() >= limit)
        {
            return $"Free preview accounts are limited to {limit} items in this collection - a membership unlocks unlimited tracking.";
        }

        return null;
    }
}
