using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The free-preview creation quota, in one place so every path that creates an item enforces it
/// identically - the ordinary CRUD create (<see cref="DataCrudControllerBase{TDto, TModel}.Post"/>) and
/// the "add a shared item to my collection" copy (<see cref="SharedWithMeController"/>). Enforcement is
/// server-side because hiding UI is not security: a non-member talking to the API directly hits the same
/// wall. Members and admins are never counted.
/// </summary>
internal static class FreeTierQuota
{
    /// <summary>
    /// Returns a ready-to-surface error message when the caller is over the free-tier limit for this
    /// collection, or null when the create may proceed. <paramref name="limitFactor"/> is 0 for
    /// member-only collections (this quota never applies there - membership is gated separately) and a
    /// per-collection multiple of <c>Features:FreeTierItemLimit</c> otherwise.
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
