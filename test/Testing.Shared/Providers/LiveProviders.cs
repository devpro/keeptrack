using System;

namespace Keeptrack.Testing.Shared.Providers;

/// <summary>
/// Whether the run may call the third-party providers, which <c>TEST_LIVE_PROVIDERS=true</c> alone allows.
/// <para>
/// Off by default, and declared rather than deduced from the keys: every package a test loads can read what its process holds,
/// and a development machine holds keys in files the hosts read by themselves.
/// </para>
/// </summary>
public static class LiveProviders
{
    public static bool Enabled { get; } =
        string.Equals(Environment.GetEnvironmentVariable("TEST_LIVE_PROVIDERS"), "true", StringComparison.OrdinalIgnoreCase);
}
