namespace KeepTrack.BlazorApp.Components.Account;

public sealed class TokenExpiredException()
    : Exception("Firebase ID token has expired. Please log in again.");
