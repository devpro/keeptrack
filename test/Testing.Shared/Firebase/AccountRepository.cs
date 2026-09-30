using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using AwesomeAssertions;

namespace Keeptrack.Testing.Shared.Firebase;

/// <summary>
/// Firebase account repository, uses Firebase API client.
/// </summary>
public static class AccountRepository
{
    /// <summary>
    /// Every resource test class authenticates independently, and xunit v3 runs them in parallel, so a full
    /// test run used to fire dozens of concurrent sign-ins against the same fixed Firebase test account within
    /// seconds - enough to trip Google Identity Platform's abuse protection and fail the whole run with 400s.
    /// The received token is valid for an hour (see ExpiresIn below), far longer than a test run, so there's no
    /// need for more than one real call per identity: cache each username's in-flight/completed sign-in behind
    /// its own Lazy, so concurrent callers for the same identity share one task instead of each starting their
    /// own.
    /// </summary>
    /// <remarks>
    /// Keyed by username, not a single field: a single cached token once meant a second identity's sign-in
    /// (<see cref="Keeptrack.BlazorApp.PlaywrightTests.Hosting.End2EndFixture"/>'s second ephemeral e2e user)
    /// silently received the first identity's already-cached token instead of its own, since the parameters
    /// were ignored once anything had signed in during the process.
    /// A real-world consequence, not a theoretical one: it made <c>AuthSmokeTest</c>'s identity-swap test pass
    /// for the wrong reason, both tokens being the same identity's.
    /// </remarks>
    private static readonly ConcurrentDictionary<string, Lazy<Task<string?>>> s_cachedTokensByUsername = new();

    private static readonly HttpClient s_httpClient = new();

    /// <summary>
    /// Authenticate. Only performs a real sign-in once per username per test run - concurrent and subsequent
    /// calls for the same username reuse the cached token/task; a different username signs in independently.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <param name="applicationKey"></param>
    /// <remarks>https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword</remarks>
    /// <returns>Received token</returns>
    public static Task<string?> AuthenticateAsync(string username, string password, string applicationKey)
    {
        return s_cachedTokensByUsername.GetOrAdd(
            username,
            _ => new Lazy<Task<string?>>(
                () => SignInAsync(username, password, applicationKey),
                LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private static async Task<string?> SignInAsync(string username, string password, string applicationKey)
    {
        var input = new { email = username, password, returnSecureToken = true };
        var url = $"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={applicationKey}";
        var response = await s_httpClient.PostAsync(url,
            new StringContent(JsonSerializer.Serialize(input, JsonSerializerOptions.Web), Encoding.UTF8, "application/json"));
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var stringResponse = await response.Content.ReadAsStringAsync();
        stringResponse.Should().NotBeNullOrEmpty();
        var output = JsonSerializer.Deserialize<VerifyPasswordResponseDto>(stringResponse, JsonSerializerOptions.Web);
        output.Should().NotBeNull();
        output.Kind.Should().Be("identitytoolkit#VerifyPasswordResponse");
        output.Email.Should().Be(username);
        output.IdToken.Should().NotBeNullOrEmpty();
        output.ExpiresIn.Should().Be("3600");
        return output.IdToken;
    }
}
