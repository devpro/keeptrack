using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Keeptrack.Testing.Shared.Providers;

/// <summary>
/// Refuses every request leaving the machine, so a test needing a provider fails instead of passing on a call nobody meant.
/// It answers 403 rather than throwing, since the resilience pipeline retries an exception, for minutes.
/// </summary>
public sealed class LoopbackOnlyHandler() : DelegatingHandler(new SocketsHttpHandler())
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        request.RequestUri is { IsLoopback: true }
            ? base.SendAsync(request, cancellationToken)
            : Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden) { RequestMessage = request });
}
