using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

/// <summary>Answers each path with the value registered for it, 404 for any other, and records what was sent.</summary>
internal sealed class StubApi : HttpMessageHandler
{
    private readonly Dictionary<string, Func<object>> _answers = [];

    public List<(string Method, string PathAndQuery, string? Body)> Requests { get; } = [];

    public StubApi Answer(string path, object value) => Answer(path, () => value);

    public StubApi Answer(string path, Func<object> value)
    {
        _answers[path] = value;
        return this;
    }

    public HttpClient CreateClient() => new(this) { BaseAddress = new Uri("https://api.example") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method.Method, request.RequestUri!.PathAndQuery, body));
        return _answers.TryGetValue(request.RequestUri.AbsolutePath, out var value)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonContent.Create(value()) }
            : new HttpResponseMessage(HttpStatusCode.NotFound);
    }
}
