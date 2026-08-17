using System;

namespace Keeptrack.BlazorApp.PlaywrightTests.Support;

public enum TraceMode
{
    Off,
    On,
    OnFailure
}

/// <summary>
/// Every e2e-harness knob in one place, all read from environment variables.
/// See docs/archived/playwright-e2e-tests-plan.md's configuration table for the full rationale per variable.
/// Application settings for the hosted apps themselves (Mongo connection string, Firebase, JWT authority...) are deliberately not read here:
/// they flow to the in-process hosts the same way any other environment variable reaches an ASP.NET Core configuration provider,
/// exactly like <c>WebApi.IntegrationTests</c> already relies on.
/// </summary>
public static class End2EndConfiguration
{
    /// <summary>
    /// Main switch.
    /// When false, every e2e test dynamically skips itself (<see cref="Xunit.Assert.SkipUnless"/>)
    /// so a plain solution-wide <c>dotnet test</c> stays green without Playwright browsers installed.
    /// </summary>
    public static bool Enabled => GetBool("E2E_ENABLED", false);

    /// <summary>
    /// Live mode: base URL of an already-running BlazorApp.
    /// Empty means self-host both apps in-process.
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

    /// <summary>
    /// Opt-in for the <see cref="Smoke.MobileScreenshotTest"/> visual-review capture.
    /// Tt adds a slow, assertion-free walkthrough to the run, so it stays off unless explicitly requested.
    /// </summary>
    public static bool MobileCheck => GetBool("E2E_MOBILE_CHECK", false);

    /// <summary>
    /// Output directory for <see cref="Smoke.MobileScreenshotTest"/>'s captures (defaults to "mobile-shots" under the test base directory).
    /// </summary>
    public static string? MobileDirectory => GetString("E2E_MOBILE_DIR");

    /// <summary>
    /// The MongoDB database the self-hosted apps run against, defaulted rather than inherited.
    /// <para>
    /// This suite and <c>WebApi.IntegrationTests</c> read the same ambient
    /// <c>Infrastructure__MongoDB__DatabaseName</c>, so an IDE that sets test environment variables once for the
    /// whole solution (Rider's Test Runner settings) can only ever give them the same database - and sharing one
    /// is not neutral: the integration suite's <c>sync-now</c> tests write the real Explore ranking, which is
    /// exactly what <c>ExploreSmokeTest</c> needs to be empty. Defaulting here makes the isolation a property of
    /// the suite instead of something a developer has to remember to toggle between runs; set this variable to
    /// override it (a shared database is still reachable, just never by accident).
    /// </para>
    /// </summary>
    public static string DatabaseName => GetString("E2E_MONGODB_DATABASE") ?? "keeptrack_e2e";

    public static bool Headless => GetBool("E2E_HEADLESS", true);

    public static float SlowMoMs => GetFloat("E2E_SLOWMO_MS", 0);

    /// <summary>
    /// <c>chromium</c>, <c>firefox</c> or <c>webkit</c>, translated into the <c>BROWSER</c> environment variable
    /// that <c>Microsoft.Playwright.Xunit.v3</c>'s own <c>PlaywrightSettingsProvider</c> reads natively,
    /// since the underlying <c>PlaywrightTest.BrowserType</c> selection has no other supported extension point.
    /// See <see cref="Smoke.SmokeTestBase"/>'s static constructor.
    /// </summary>
    public static string Browser => GetString("E2E_BROWSER") ?? "chromium";

    public static TraceMode Trace => (GetString("E2E_TRACE") ?? "on-failure").ToLowerInvariant() switch
    {
        "off" => TraceMode.Off,
        "on" => TraceMode.On,
        _ => TraceMode.OnFailure
    };

    private static string? GetString(string name)
    {
        return Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Process) is { Length: > 0 } value ? value : null;
    }

    private static bool GetBool(string name, bool defaultValue)
    {
        return bool.TryParse(GetString(name), out var value) ? value : defaultValue;
    }

    private static float GetFloat(string name, float defaultValue)
    {
        return float.TryParse(GetString(name), out var value) ? value : defaultValue;
    }
}
