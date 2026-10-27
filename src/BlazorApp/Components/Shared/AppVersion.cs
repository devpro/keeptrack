using System.Reflection;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// The running build's version, from the informational version that <c>Directory.Build.props</c> and the SDK's source revision produce.
/// </summary>
public static class AppVersion
{
    private const int ShortHashLength = 7;

    public static string Current { get; } =
        Format(typeof(AppVersion).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion);

    public static string Format(string? informationalVersion)
    {
        if (string.IsNullOrEmpty(informationalVersion))
        {
            return "unknown";
        }

        // The SDK appends the full 40-character commit hash, which is unreadable in a header and as identifying at git's usual 7.
        var plus = informationalVersion.IndexOf('+');
        return plus >= 0 && informationalVersion.Length - plus - 1 > ShortHashLength
            ? informationalVersion[..(plus + 1 + ShortHashLength)]
            : informationalVersion;
    }
}
