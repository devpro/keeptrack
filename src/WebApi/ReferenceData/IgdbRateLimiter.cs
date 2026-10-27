using System.Net;
using System.Threading.RateLimiting;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Paces IGDB requests to the documented 4 per second, queueing rather than failing when callers come faster.
/// <para>
/// A singleton apart from its handler, since <see cref="IHttpClientFactory"/> rebuilds a <see cref="DelegatingHandler"/> on every rotation,
/// which would reset a budget the handler owned.
/// </para>
/// <para>
/// The bucket is per process, so several replicas can exceed the limit together, and the resilience handler retries the occasional 429.
/// Only the reference sync sustains this rate, interactive traffic being a handful of calls.
/// </para>
/// </summary>
public sealed class IgdbRateLimiter : IDisposable
{
    /// <summary>IGDB's documented ceiling: 4 requests per second, up to 8 open at once.</summary>
    private const int RequestsPerSecond = 4;

    private readonly TokenBucketRateLimiter _limiter = new(new TokenBucketRateLimiterOptions
    {
        TokenLimit = RequestsPerSecond,
        TokensPerPeriod = RequestsPerSecond,
        ReplenishmentPeriod = TimeSpan.FromSeconds(1),
        AutoReplenishment = true,
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        QueueLimit = MaxQueuedRequests
    });

    /// <summary>
    /// How many callers may wait for a token before the handler answers 429 instead.
    /// <para>
    /// Bounded: at <see cref="RequestsPerSecond"/> this is a few seconds of backlog, within the resilience total timeout, so a burst waits its turn.
    /// An unbounded queue could wait forever, since <c>HttpClient.Timeout</c> is infinite, and a stuck pod is worse than a failing one.
    /// </para>
    /// <para>
    /// Overflowing is cheap, since this handler sits inside the resilience handler, which retries the 429 with backoff and so paces a sync pass.
    /// </para>
    /// </summary>
    private const int MaxQueuedRequests = 32;

    public ValueTask<RateLimitLease> AcquireAsync(CancellationToken cancellationToken) =>
        _limiter.AcquireAsync(1, cancellationToken);

    public void Dispose() => _limiter.Dispose();
}

/// <summary>
/// Applies <see cref="IgdbRateLimiter"/> to every IGDB request.
/// </summary>
public class IgdbRateLimitHandler(IgdbRateLimiter limiter) : DelegatingHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using var lease = await limiter.AcquireAsync(cancellationToken);
        return lease.IsAcquired
            ? await base.SendAsync(request, cancellationToken)
            : new HttpResponseMessage(HttpStatusCode.TooManyRequests) { RequestMessage = request };
    }
}
