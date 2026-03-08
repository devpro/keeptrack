namespace KeepTrack.BlazorApp.Services;

public interface ITokenStore
{
    void Store(string uid, string idToken, DateTimeOffset expiry);

    (string? token, DateTimeOffset expiry) Get(string uid);

    void Remove(string uid);
}
