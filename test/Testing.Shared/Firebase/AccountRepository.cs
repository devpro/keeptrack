using System;
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
    /// need for more than one real call: cache the in-flight/completed sign-in behind a Lazy so concurrent
    /// callers share the same task instead of each starting their own.
    /// </summary>
    private static Lazy<Task<string?>>? s_cachedToken;

    /// <summary>
    /// Authenticate. Only performs a real sign-in once per test run - concurrent and subsequent calls reuse the
    /// cached token/task.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <param name="applicationKey"></param>
    /// <remarks>https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword</remarks>
    /// <returns>Received token</returns>
    public static Task<string?> AuthenticateAsync(string username, string password, string applicationKey)
    {
        return LazyInitializer.EnsureInitialized(
            ref s_cachedToken,
            () => new Lazy<Task<string?>>(
                () => SignInAsync(username, password, applicationKey),
                LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private static async Task<string?> SignInAsync(string username, string password, string applicationKey)
    {
        using var httpClient = new HttpClient();

        var input = new
        {
            email = username,
            password,
            returnSecureToken = true
        };
        var url = $"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={applicationKey}";
        var response = await httpClient.PostAsync(url, new StringContent(JsonSerializer.Serialize(input, JsonSerializerOptions.Web), Encoding.UTF8, "application/json"));
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
