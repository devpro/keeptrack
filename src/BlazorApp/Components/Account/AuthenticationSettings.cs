namespace Keeptrack.BlazorApp.Components.Account;

public sealed class AuthenticationSettings(AuthenticationMode mode)
{
    /// <summary>The auth cookie's lifetime, which a local token matches since nothing refreshes it.</summary>
    public static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);

    public AuthenticationMode Mode { get; } = mode;

    /// <summary>
    /// Firebase when unset, so a deployment that predates the setting keeps its sign-in.
    /// Local is refused in Production, since its form signs anyone in as anyone, admin included.
    /// </summary>
    public static AuthenticationMode ResolveMode(IConfiguration configuration, string environmentName)
    {
        var value = configuration["Authentication:Mode"];
        if (string.IsNullOrEmpty(value)) return AuthenticationMode.Firebase;

        if (!Enum.TryParse<AuthenticationMode>(value, ignoreCase: true, out var mode) || !Enum.IsDefined(mode))
        {
            throw new InvalidOperationException($"Authentication:Mode \"{value}\" is unknown, expected one of: {string.Join(", ", Enum.GetNames<AuthenticationMode>())}.");
        }

        if (mode == AuthenticationMode.Local && string.Equals(environmentName, Environments.Production, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Authentication:Mode Local signs users in without a password and is refused in the Production environment.");
        }

        return mode;
    }
}
