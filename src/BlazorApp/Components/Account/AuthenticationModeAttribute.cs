namespace Keeptrack.BlazorApp.Components.Account;

/// <summary>Ties a controller to one mode, outside which <see cref="AuthenticationModeControllerFilter"/> removes it.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthenticationModeAttribute(AuthenticationMode mode) : Attribute
{
    public AuthenticationMode Mode { get; } = mode;
}
