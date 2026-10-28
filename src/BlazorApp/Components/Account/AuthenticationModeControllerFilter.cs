using System.Reflection;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>
/// Removes the controllers of the other mode, so their endpoints answer 404 rather than run without what they need:
/// the Firebase endpoints without a Firebase app, the password-less local sign-in on a Firebase host.
/// Runs after the default provider, which discovers every controller.
/// </summary>
public sealed class AuthenticationModeControllerFilter(AuthenticationMode mode) : IApplicationFeatureProvider<ControllerFeature>
{
    public void PopulateFeature(IEnumerable<ApplicationPart> parts, ControllerFeature feature)
    {
        var otherModeControllers = feature.Controllers
            .Where(controller => controller.GetCustomAttribute<AuthenticationModeAttribute>() is { } attribute && attribute.Mode != mode)
            .ToList();
        foreach (var controller in otherModeControllers)
        {
            feature.Controllers.Remove(controller);
        }
    }
}
