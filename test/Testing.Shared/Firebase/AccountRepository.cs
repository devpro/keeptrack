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
    /// Every resource test class authenticates independently, and xunit v3 runs them in parallel,
    /// so dozens of concurrent sign-ins for one Firebase account would trip Google Identity Platform's abuse protection and fail the run with 400s.
    /// The token is valid for an hour (see ExpiresIn below), longer than a run,
    /// so each username's sign-in is cached behind its own Lazy, and concurrent callers for one identity share one task.
    /// </summary>
    /// <remarks>
    /// Keyed by username, not one field, or a second identity's sign-in
    /// (<see cref="Keeptrack.BlazorApp.PlaywrightTests.Hosting.End2EndFixture"/>'s second ephemeral user) would get the first identity's cached token.
    /// <c>AuthSmokeTest</c>'s identity-swap test would then pass for the wrong reason, both tokens being one identity's.
    /// </remarks>
    private static readonly ConcurrentDictionary<string, Lazy<Task<string?>>> s_cachedTokensByUsername = new();

    private static readonly HttpClient s_httpClient = new();

    /// <summary>
    /// Authenticate.
    /// Signs in for real once per username per test run, later and concurrent calls for that username reusing the cached task, and a different username signing in independently.
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
