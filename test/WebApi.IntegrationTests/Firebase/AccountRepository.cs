using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;

namespace Keeptrack.WebApi.IntegrationTests.Firebase;

/// <summary>
/// Firebase account repository, uses Firebase API client.
/// </summary>
public static class AccountRepository
{
    /// <summary>
    /// Authenticate.
    /// </summary>
    /// <param name="username"></param>
    /// <param name="password"></param>
    /// <param name="applicationKey"></param>
    /// <remarks>https://cloud.google.com/identity-platform/docs/reference/rest/v1/accounts/signInWithPassword</remarks>
    /// <returns>Received token</returns>
    public static async Task<string?> AuthenticateAsync(string username, string password, string applicationKey)
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
