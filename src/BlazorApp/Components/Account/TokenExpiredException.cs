namespace Keeptrack.BlazorApp.Components.Account;

public sealed class TokenExpiredException()
    : Exception("Authentication token has expired. Please log in again.");
