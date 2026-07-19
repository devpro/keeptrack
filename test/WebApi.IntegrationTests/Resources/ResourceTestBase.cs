using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Testing.Shared.Firebase;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

public abstract class ResourceTestBase(KestrelWebAppFactory<Program> factory)
    : IClassFixture<KestrelWebAppFactory<Program>>, IAsyncLifetime
{
    private const string MediaTypeJson = "application/json";

    /// <summary>
    /// Exposes the factory to subclasses that also need a DI scope (e.g. to seed data directly via a
    /// repository) alongside the HTTP helpers below - avoids a second, redundant capture of the same
    /// constructor parameter as its own field.
    /// </summary>
    protected KestrelWebAppFactory<Program> Factory => factory;

    private HttpClient _httpClient = null!;

    public ValueTask InitializeAsync()
    {
        _httpClient = new HttpClient { BaseAddress = new Uri(factory.ServerAddress) };
        return ValueTask.CompletedTask;
    }

    public ValueTask DisposeAsync()
    {
        _httpClient?.Dispose();
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
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

        var stringResponse = await response.Content.ReadAsStringAsync();
        stringResponse.Should().NotBeNullOrEmpty();
        var output = JsonSerializer.Deserialize<T>(stringResponse, JsonSerializerOptions.Web);
        output.Should().NotBeNull();
        return output;
    }

    protected async Task<T> PostAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.Created)
    {
        var bodyContent = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, MediaTypeJson);
        var response = await _httpClient.PostAsync(url, bodyContent);
        response.StatusCode.Should().Be(httpStatusCode);

        var stringResponse = await response.Content.ReadAsStringAsync();
        var output = JsonSerializer.Deserialize<T>(stringResponse, JsonSerializerOptions.Web);
        output.Should().NotBeNull();
        return output;
    }

    /// <summary>
    /// For endpoints whose request and response bodies are different types (e.g. a create request DTO
    /// answered with the created resource) - the single-type overload above covers the common
    /// same-DTO-both-ways CRUD case.
    /// </summary>
    protected async Task<TResult> PostAsync<TBody, TResult>(string url, TBody body, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        var bodyContent = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, MediaTypeJson);
        var response = await _httpClient.PostAsync(url, bodyContent);
        response.StatusCode.Should().Be(httpStatusCode);

        var stringResponse = await response.Content.ReadAsStringAsync();
        var output = JsonSerializer.Deserialize<TResult>(stringResponse, JsonSerializerOptions.Web);
        output.Should().NotBeNull();
        return output;
    }

    protected async Task PutAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.NoContent)
    {
        var bodyContent = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, MediaTypeJson);
        var response = await _httpClient.PutAsync(url, bodyContent);
        response.StatusCode.Should().Be(httpStatusCode);
    }

    /// <summary>
    /// For POST endpoints that return no body (e.g. 204 No Content, like <c>POST /api/reference-data/link</c>) -
    /// the other <c>PostAsync</c> overloads all assume a JSON response body and would throw trying to
    /// deserialize an empty one. Same status-check-only shape as <see cref="PutAsync{T}"/>, just over POST.
    /// </summary>
    protected async Task PostNoContentAsync<T>(string url, T body, HttpStatusCode httpStatusCode = HttpStatusCode.NoContent)
    {
        var bodyContent = new StringContent(JsonSerializer.Serialize(body, JsonSerializerOptions.Web), Encoding.UTF8, MediaTypeJson);
        var response = await _httpClient.PostAsync(url, bodyContent);
        response.StatusCode.Should().Be(httpStatusCode);
    }

    protected async Task<T> PostFileAsync<T>(string url, string fieldName, byte[] fileContent, string fileName, HttpStatusCode httpStatusCode = HttpStatusCode.OK)
    {
        using var content = new MultipartFormDataContent();
        using var byteContent = new ByteArrayContent(fileContent);
        content.Add(byteContent, fieldName, fileName);

        var response = await _httpClient.PostAsync(url, content);
        response.StatusCode.Should().Be(httpStatusCode);

        var stringResponse = await response.Content.ReadAsStringAsync();
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

    protected async Task Authenticate()
    {
        var token = await AccountRepository.AuthenticateAsync(
            FirebaseConfiguration.Username, FirebaseConfiguration.Password, FirebaseConfiguration.ApplicationKey);
        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}
