using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Keeptrack.Common.Hosting.Authentication;

/// <summary>
/// The shared HS256 key of local authentication, read the same way by the side that signs (BlazorApp) and the side that validates (WebApi).
/// </summary>
public static class LocalSigningKey
{
    /// <summary>HS256 needs a key at least as long as its 256-bit hash, and IdentityModel refuses a shorter one only when the first token is signed.</summary>
    private const int MinimumBytes = 32;

    public static SymmetricSecurityKey Decode(string base64)
    {
        byte[] bytes;
        try
        {
            bytes = Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("The local authentication signing key must be base64, for example the output of `openssl rand -base64 32`.");
        }

        return bytes.Length < MinimumBytes
            ? throw new InvalidOperationException($"The local authentication signing key must decode to at least {MinimumBytes} bytes.")
            : new SymmetricSecurityKey(bytes);
    }

    public static string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(MinimumBytes));
}
