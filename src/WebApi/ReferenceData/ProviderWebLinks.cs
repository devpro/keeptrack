using Keeptrack.Domain.Services;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The one place a provider's public page URL is spelled: the page a human opens to read about a title, not the API endpoint.
/// Declared beside the clients rather than where a link is rendered, so a host is never spelled twice.
/// <para>
/// Only pages derivable from a stored id live here.
/// IGDB and RAWG key their pages on a slug, so those come from the provider itself (IGDB's <c>url</c>, RAWG's <c>slug</c>)
/// and are stored with the entry (see <see cref="Keeptrack.Domain.Models.ExploreCatalogueEntryModel.WebUrls"/>).
/// </para>
/// </summary>
public static class ProviderWebLinks
{
    /// <summary>A movie's page on themoviedb.org, from its TMDB id.</summary>
    public static string TmdbMovie(string tmdbId) => $"https://www.themoviedb.org/movie/{tmdbId}";

    /// <summary>A show's page on themoviedb.org, from its TMDB id, TMDB separating movie and TV pages.</summary>
    public static string TmdbTvShow(string tmdbId) => $"https://www.themoviedb.org/tv/{tmdbId}";

    /// <summary>
    /// A title's page on imdb.com, from the IMDb id (<c>tt0111161</c>) TMDB exposes, stable on that id.
    /// </summary>
    public static string Imdb(string imdbId) => $"https://www.imdb.com/title/{imdbId}/";

    /// <summary>A game's page on rawg.io, from the slug RAWG returns beside every listing entry.</summary>
    public static string Rawg(string slug) => $"https://rawg.io/games/{slug}";

    /// <summary>
    /// Reads back the identifier a provider keys a page on, the last path segment of a pasted URL or a bare numeric id,
    /// so an admin names a title by address when no search reaches it.
    /// The inverse of the builders above, kept beside them.
    /// <para>
    /// Nothing else counts as an identifier.
    /// A bare word is an ordinary search ("Half-Life" looks like a slug), so only an address or a number skips the search, or a wrong guess would silently search for nothing.
    /// </para>
    /// </summary>
    public static bool TryReadIdentifier(string text, out string identifier)
    {
        identifier = string.Empty;
        var trimmed = text.Trim();
        if (trimmed.Length == 0) return false;

        if (trimmed.All(char.IsAsciiDigit))
        {
            identifier = trimmed;
            return true;
        }

        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var url) || (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps))
        {
            return false;
        }

        identifier = url.Segments.Select(segment => segment.Trim('/')).LastOrDefault(segment => segment.Length > 0) ?? string.Empty;
        return identifier.Length > 0;
    }
}
