using System.Net;
using System.Threading.RateLimiting;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Paces outgoing IGDB requests to the 4 requests/second the API documents, queueing rather than failing when
/// callers arrive faster.
/// <para>
/// A singleton holding the bucket, separate from the handler that uses it, because a
/// <see cref="DelegatingHandler"/> registered with <c>AddHttpMessageHandler</c> is rebuilt every time
/// <see cref="IHttpClientFactory"/> rotates its handler chain - a limiter owned by the handler would silently
/// reset its budget on every rotation.
/// </para>
/// <para>
/// The bucket is per process, so N replicas can still collectively exceed the limit; the standard resilience
/// handler's retry covers the occasional 429 that results - IGDB's own and this one's alike. Only the nightly
/// reference sync can sustain this rate at all; interactive traffic is a handful of calls.
/// </para>
/// </summary>
public sealed class IgdbRateLimiter : IDisposable
{
    /// <summary>IGDB's documented ceiling: 4 requests per second, with up to 8 open at once.</summary>
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
    /// How many callers may wait for a token before the handler stops queueing and answers 429 instead.
    /// <para>
    /// Bounded on purpose. At <see cref="RequestsPerSecond"/> this is a few seconds of backlog, comfortably
    /// inside the resilience handler's total-request timeout, so an ordinary burst waits its turn. An
    /// unbounded queue would instead let a caller wait indefinitely - the typed client's own
    /// <c>HttpClient.Timeout</c> is <c>Timeout.InfiniteTimeSpan</c> by design, so nothing else would ever
    /// break that wait, and a pod stuck in one is worse than a pod that fails and gets restarted.
    /// </para>
    /// <para>
    /// Overflowing is cheap rather than fatal precisely because this handler sits inside the resilience
    /// handler: the 429 is retried with backoff, which paces a bulk sync pass instead of failing it.
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
