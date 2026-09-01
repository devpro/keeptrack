using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Testing.Shared.Firebase;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public abstract class ResourceTestBase(KestrelWebAppFactory<Program> factory)
    : DatabaseTestBase(factory)
{
    private const string MediaTypeJson = "application/json";

    private HttpClient _httpClient = null!;

    public override ValueTask InitializeAsync()
    {
        _httpClient = new HttpClient { BaseAddress = new Uri(Factory.ServerAddress) };
        return base.InitializeAsync();
    }

    public override async ValueTask DisposeAsync()
    {
        try
        {
            // the registered cleanups are HTTP calls on this very client, so it has to outlive them
            await base.DisposeAsync();
        }
        finally
        {
            _httpClient?.Dispose();
        }
    }

    /// <summary>
    /// Registers a resource created over the API for deletion when the test ends. Prefer
    /// <see cref="CreateAsync{T}"/>, which does this for you; use this directly for the endpoints whose
    /// create response isn't the resource itself (an import commit, a share grant read back from a list).
    /// <para>
    /// The delete is status-agnostic on purpose: plenty of tests delete their own subject as part of what
    /// they assert (revoking a share, the cascade-delete cases), and a cleanup that insisted on 204 would
    /// turn that correct behavior into a failure.
    /// </para>
    /// </summary>
    protected void TrackResource(string resourceEndpoint, string? id)
    {
        if (string.IsNullOrEmpty(id)) return;

        TrackCleanup(async () =>
        {
            using var response = await _httpClient.DeleteAsync($"{resourceEndpoint.TrimEnd('/')}/{id}");
        });
    }

    /// <summary>
    /// Registers a "delete whatever this endpoint lists for this search term" cleanup.
    /// <para>
    /// This is the import endpoints' shape: a commit creates items the test never learns the ids of, so the
    /// only handle on them is the (unique, synthetic) title the fixture used. Registered before the commit
    /// rather than after, so a partially-successful commit is still cleaned up. Every list endpoint shares
    /// the one <c>PagedResult</c> shape, so this single helper serves all of them.
    /// </para>
    /// </summary>
    protected void TrackResourcesMatching<TDto>(string resourceEndpoint, string searchTerm)
        where TDto : IHasId
    {
        TrackCleanup(async () =>
        {
            var page = await GetAsync<PagedResult<TDto>>($"{resourceEndpoint}?search={Uri.EscapeDataString(searchTerm)}");
            foreach (var item in page.Items)
            {
                TrackResource(resourceEndpoint, item.Id);
            }
        });
    }

    /// <summary>
    /// Posts a new resource and registers it for deletion in one step, so there is no window in which a
    /// created item isn't yet tracked. This is the shape almost every test wants.
    /// </summary>
    protected async Task<T> CreateAsync<T>(string resourceEndpoint, T body, HttpStatusCode httpStatusCode = HttpStatusCode.Created)
        where T : IHasId
    {
        var created = await PostAsync(resourceEndpoint, body, httpStatusCode);
        TrackResource(resourceEndpoint, created.Id);
        return created;
    }

    protected async Task GetAsync(string url, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        var response = await _httpClient.GetAsync(url);
        response.StatusCode.Should().Be(httpStatusCode);
    }

    protected async Task<T> GetAsync<T>(string url, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        var response = await _httpClient.GetAsync(url);
        response.StatusCode.Should().Be(httpStatusCode);

        return await ReadJsonAsync<T>(response);
    }

    /// <summary>
    /// A GET whose answer comes from a live third-party provider (the reference-data search endpoints), which
    /// can be down or degraded while this codebase is perfectly correct. A 502 says exactly that - the
    /// resilience pipeline gave up on the provider, see <c>ApiExceptionFilterAttribute</c> - so the test skips
    /// instead of reddening CI over someone else's outage.
    /// <para>
    /// Deliberately narrow: only 502. A 500 is this API failing and must still fail the test. Learned from a
    /// real CI failure - Open Library's <c>search.json</c> went to 52s and then 503/504, past the 40s total
    /// budget, and the resulting 500 read as a broken endpoint.
    /// </para>
    /// </summary>
    protected async Task<T> GetThroughLiveProviderAsync<T>(string url, string provider)
    {
        var response = await _httpClient.GetAsync(url);
        SkipWhenProviderUnavailable(response.StatusCode, provider);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        return await ReadJsonAsync<T>(response);
    }

    protected async Task<T> PostAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.Created)
    {
        var response = await _httpClient.PostAsync(url, JsonBody(body));
        response.StatusCode.Should().Be(httpStatusCode);

        return await ReadJsonAsync<T>(response);
    }

    /// <summary>
    /// For endpoints whose request and response bodies are different types (e.g. a create request DTO
    /// answered with the created resource) - the single-type overload above covers the common
    /// same-DTO-both-ways CRUD case.
    /// </summary>
    protected async Task<TResult> PostAsync<TBody, TResult>(string url, TBody body, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        var response = await _httpClient.PostAsync(url, JsonBody(body));
        response.StatusCode.Should().Be(httpStatusCode);

        return await ReadJsonAsync<TResult>(response);
    }

    protected async Task PutAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.NoContent)
    {
        var response = await _httpClient.PutAsync(url, JsonBody(body));
        response.StatusCode.Should().Be(httpStatusCode);
    }

    /// <summary>
    /// For POST endpoints that return no body (e.g. 204 No Content, like <c>POST /api/reference-data/link</c>) -
    /// the other <c>PostAsync</c> overloads all assume a JSON response body and would throw trying to
    /// deserialize an empty one. Same status-check-only shape as <see cref="PutAsync{T}"/>, just over POST.
    /// </summary>
    protected async Task PostNoContentAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.NoContent)
    {
        var response = await _httpClient.PostAsync(url, JsonBody(body));
        response.StatusCode.Should().Be(httpStatusCode);
    }

    /// <summary>
    /// A no-body POST whose answer comes from a live third-party provider, returning the resource it produced -
    /// same 502-skips-rather-than-fails contract as <see cref="GetThroughLiveProviderAsync{T}"/>, for the
    /// actions that both reach a provider and answer with the updated item (the detail page's
    /// "check for reference match").
    /// </summary>
    protected async Task<T> PostThroughLiveProviderAsync<T>(string url, string provider)
    {
        var response = await _httpClient.PostAsync(url, null);
        SkipWhenProviderUnavailable(response.StatusCode, provider);
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        return await ReadJsonAsync<T>(response);
    }

    /// <summary>
    /// The no-body POST counterpart of <see cref="GetThroughLiveProviderAsync{T}"/>, for the actions that
    /// reach the provider again after a search (linking re-fetches the chosen candidate's details).
    /// </summary>
    protected async Task PostNoContentThroughLiveProviderAsync<T>(string url, T body, string provider)
    {
        var response = await _httpClient.PostAsync(url, JsonBody(body));
        SkipWhenProviderUnavailable(response.StatusCode, provider);
        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }

    private static void SkipWhenProviderUnavailable(HttpStatusCode statusCode, string provider) =>
        Assert.SkipWhen(statusCode == HttpStatusCode.BadGateway,
            $"{provider} could not be reached (502 Bad Gateway); skipping rather than failing on a third-party outage.");

    protected async Task<T> PostFileAsync<T>(string url, string fieldName, byte[] fileContent, string fileName, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        using var content = new MultipartFormDataContent();
        using var byteContent = new ByteArrayContent(fileContent);
        content.Add(byteContent, fieldName, fileName);

        var response = await _httpClient.PostAsync(url, content);
        response.StatusCode.Should().Be(httpStatusCode);

        return await ReadJsonAsync<T>(response);
    }

    private static StringContent JsonBody<T>(T body) =>
        new(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, MediaTypeJson);

    private static async Task<T> ReadJsonAsync<T>(HttpResponseMessage response)
    {
        var stringResponse = await response.Content.ReadAsStringAsync();
        stringResponse.Should().NotBeNullOrEmpty();
        var output = JsonSerializer.Deserialize<T>(stringResponse, JsonSerializerOptions.Web);
        output.Should().NotBeNull();
        return output;
    }

    protected async Task DeleteAsync(string url, HttpStatusCode httpStatusCode = HttpStatusCode.NoContent)
    {
        var response = await _httpClient.DeleteAsync(url);
        response.StatusCode.Should().Be(httpStatusCode);

        await response.Content.ReadAsStringAsync();
    }

    /// <summary>
    /// The signed-in caller's Firebase uid - the same value the API stamps as <c>OwnerId</c> on everything
    /// this test creates (see <c>ControllerBaseExtensions.GetUserId</c>). Available after
    /// <see cref="Authenticate"/>, for the few cleanups that can only identify a document by its owner.
    /// </summary>
    protected string AuthenticatedUserId { get; private set; } = "";

    protected async Task Authenticate()
    {
        var token = await AccountRepository.AuthenticateAsync(
            FirebaseConfiguration.Username, FirebaseConfiguration.Password, FirebaseConfiguration.ApplicationKey);
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        AuthenticatedUserId = ReadUserIdClaim(token!);
    }

    /// <summary>
    /// Reads the <c>user_id</c> claim straight out of the token's payload segment. No signature check: the
    /// API already validates the token on every call, and this only needs the same identity the server will
    /// derive, to scope a cleanup by owner.
    /// </summary>
    private static string ReadUserIdClaim(string token)
    {
        var payload = token.Split('.')[1];
        var padded = payload.Replace('-', '+').Replace('_', '/').PadRight((payload.Length + 3) / 4 * 4, '=');
        using var document = JsonDocument.Parse(Convert.FromBase64String(padded));
        return document.RootElement.GetProperty("user_id").GetString()!;
    }
}
