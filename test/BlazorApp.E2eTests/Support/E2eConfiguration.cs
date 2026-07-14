using System;

namespace Keeptrack.BlazorApp.E2eTests.Support;

public enum TraceMode
{
    Off,
    On,
    OnFailure
}

/// <summary>
/// Every e2e-harness knob in one place, all read from environment variables - see
/// docs/playwright-e2e-tests-plan.md's configuration table for the full rationale per variable.
/// Application settings for the hosted apps themselves (Mongo connection string, Firebase, JWT authority...)
/// are deliberately not read here: they flow to the in-process hosts the same way any other environment
/// variable reaches an ASP.NET Core configuration provider, exactly like <c>WebApi.IntegrationTests</c>
/// already relies on today.
/// </summary>
public static class E2eConfiguration
{
    /// <summary>
    /// Master switch. When false, every e2e test dynamically skips itself (<see cref="Xunit.Assert.SkipUnless"/>)
    /// so a plain solution-wide <c>dotnet test</c> stays green without Playwright browsers installed.
    /// </summary>
    public static bool Enabled => GetBool("E2E_ENABLED", false);

    /// <summary>
    /// Live mode: base URL of an already-running BlazorApp. Empty means self-host both apps in-process.
    /// </summary>
    public static string? TargetUrl => GetString("E2E_TARGET_URL");

    /// <summary>
    /// Live mode: base URL of the matching WebApi, required for seeding/cleanup unless <see cref="ReadOnly"/>.
    /// </summary>
    public static string? WebApiUrl => GetString("E2E_WEBAPI_URL");

    public static bool IsLiveMode => TargetUrl is not null;

    /// <summary>
    /// Skips every mutating test, user creation, and seeding.
    /// </summary>
    public static bool ReadOnly => GetBool("E2E_READONLY", false);

    /// <summary>
    /// Existing account email. Empty triggers ephemeral admin user creation (integration mode only).
    /// </summary>
    public static string? Username => GetString("E2E_USERNAME");

    public static string? Password => GetString("E2E_PASSWORD");

    public static bool Headless => GetBool("E2E_HEADLESS", true);

    public static float SlowMoMs => GetFloat("E2E_SLOWMO_MS", 0);

    /// <summary>
    /// <c>chromium</c>, <c>firefox</c> or <c>webkit</c> - translated into the <c>BROWSER</c> environment
    /// variable that <c>Microsoft.Playwright.Xunit.v3</c>'s own <c>PlaywrightSettingsProvider</c> reads
    /// natively, since the underlying <c>PlaywrightTest.BrowserType</c> selection has no other supported
    /// extension point. See <see cref="Smoke.SmokeTestBase"/>'s static constructor.
    /// </summary>
    public static string Browser => GetString("E2E_BROWSER") ?? "chromium";

    public static TraceMode Trace => (GetString("E2E_TRACE") ?? "on-failure").ToLowerInvariant() switch
    {
        "off" => TraceMode.Off,
        "on" => TraceMode.On,
        _ => TraceMode.OnFailure
    };

    private static string? GetString(string name)
        => Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process) is { Length: > 0 } value ? value : null;

    private static bool GetBool(string name, bool defaultValue)
        => bool.TryParse(GetString(name), out var value) ? value : defaultValue;

    private static float GetFloat(string name, float defaultValue)
        => float.TryParse(GetString(name), out var value) ? value : defaultValue;
}
