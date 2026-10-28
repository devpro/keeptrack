using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Keeptrack.Common.Hosting.Authentication;
using Keeptrack.Testing.Shared.Firebase;

namespace Keeptrack.Testing.Shared.Authentication;

/// <summary>
/// The run's authentication mode and the run's own identity, so every suite runs with or without Firebase (see docs/authentication.md).
/// <para>
/// <c>TEST_AUTHENTICATION_MODE</c> (<c>firebase</c> or <c>local</c>) decides when set.
/// Otherwise the run is Firebase when <c>FIREBASE_APIKEY</c> is set, since a developer or CI holding Firebase test credentials expects them used,
/// and local when it is not, since Firebase cannot be reached then anyway.
/// </para>
/// </summary>
public static class TestAuthentication
{
    public const string LocalIssuer = "keeptrack-tests";

    public const string LocalAudience = "keeptrack-tests";

    /// <summary>The local identity matches the Firebase test user's role, so admin-gated tests run the same in both modes.</summary>
    public const string PrimaryRole = "admin";

    private const string LocalPrimaryEmail = "integration-tests@keeptrack.test";

    /// <summary>Generated per run, so no key is ever configured or committed for tests.</summary>
    public static string LocalSigningKey { get; } = Common.Hosting.Authentication.LocalSigningKey.Generate();

    private static readonly LocalTokenIssuer s_localTokenIssuer =
        new(new LocalTokenSettings { SigningKey = LocalSigningKey, Issuer = LocalIssuer, Audience = LocalAudience });

    public static bool IsLocal { get; } = ResolveIsLocal();

    /// <summary>The run's own identity: the Firebase test user, or a fixed local address, reaching the same data on every run.</summary>
    public static string PrimaryEmail => IsLocal ? LocalPrimaryEmail : FirebaseConfiguration.Username;

    public static async Task<string> GetPrimaryTokenAsync() =>
        IsLocal
            ? IssueLocalToken(PrimaryEmail, PrimaryRole)
            : await AccountRepository.AuthenticateAsync(FirebaseConfiguration.Username, FirebaseConfiguration.Password, FirebaseConfiguration.ApplicationKey)
              ?? throw new InvalidOperationException("Firebase sign-in did not return an id token.");

    /// <summary>A token the hosts configured by this class accept, valid longer than any run.</summary>
    public static string IssueLocalToken(string email, string? role) =>
        s_localTokenIssuer.Issue(email, role, DateTimeOffset.UtcNow, TimeSpan.FromHours(8));

    /// <summary>
    /// WebApi configuration overrides for the run's mode: none in Firebase mode, where the environment configures the authority,
    /// and the run's signing key in local mode.
    /// </summary>
    public static KeyValuePair<string, string?>[] WebApiConfiguration() => IsLocal ? LocalWebApiConfiguration() : [];

    /// <summary>
    /// Validates the tokens of <see cref="IssueLocalToken"/> whatever the run's mode.
    /// The authority is blanked, since the environment may set Firebase's and the WebApi refuses both.
    /// </summary>
    public static KeyValuePair<string, string?>[] LocalWebApiConfiguration() =>
    [
        new("Authentication:JwtBearer:Authority", ""),
        new("Authentication:JwtBearer:SigningKey", LocalSigningKey),
        new("Authentication:JwtBearer:TokenValidation:Issuer", LocalIssuer),
        new("Authentication:JwtBearer:TokenValidation:Audience", LocalAudience)
    ];

    /// <summary>
    /// Puts an in-process BlazorApp in the run's mode.
    /// Environment variables, since BlazorApp reads its mode before the host is built, earlier than a factory override reaches.
    /// </summary>
    public static void ConfigureBlazorAppEnvironment()
    {
        if (!IsLocal) return;

        Environment.SetEnvironmentVariable("Authentication__Mode", "Local");
        Environment.SetEnvironmentVariable("Authentication__Local__SigningKey", LocalSigningKey);
        Environment.SetEnvironmentVariable("Authentication__Local__Issuer", LocalIssuer);
        Environment.SetEnvironmentVariable("Authentication__Local__Audience", LocalAudience);
    }

    private static bool ResolveIsLocal()
    {
        var mode = Environment.GetEnvironmentVariable("TEST_AUTHENTICATION_MODE");
        return mode?.ToLowerInvariant() switch
        {
            "local" => true,
            "firebase" => false,
            null or "" => string.IsNullOrEmpty(Environment.GetEnvironmentVariable("FIREBASE_APIKEY")),
            _ => throw new InvalidOperationException($"TEST_AUTHENTICATION_MODE \"{mode}\" is unknown, expected firebase or local.")
        };
    }
}
