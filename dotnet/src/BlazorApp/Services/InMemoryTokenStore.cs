using System.Collections.Concurrent;

namespace KeepTrack.BlazorApp.Services;

public sealed class InMemoryTokenStore : ITokenStore
{
    private record Entry(string Token, DateTimeOffset Expiry);

    private readonly ConcurrentDictionary<string, Entry> _store = new();

    public void Store(string uid, string idToken, DateTimeOffset expiry) =>
        _store[uid] = new Entry(idToken, expiry);

    public (string? token, DateTimeOffset expiry) Get(string uid) =>
        _store.TryGetValue(uid, out var e) ? (e.Token, e.Expiry) : (null, DateTimeOffset.MinValue);

    public void Remove(string uid) =>
        _store.TryRemove(uid, out _);
}
