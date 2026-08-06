namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The one place a provider's *public web page* URL is spelled - the page a human opens to read more about a
/// title, as opposed to the API endpoint the app calls. Declared here beside the clients rather than in
/// whichever feature happens to render a link, for the same reason <see cref="RatingSourceCatalog"/> holds the
/// source keys: several places will want them, and a second spelling of the same host is how one of them
/// silently rots.
/// <para>
/// Only the providers whose page URL is *derivable from the id we already store* live here. IGDB and RAWG key
/// their pages on a slug, which no amount of arithmetic turns an id into, so those come back from the provider
/// itself (IGDB's <c>url</c> field, RAWG's <c>slug</c>) and are stored alongside the entry - see
/// <see cref="Keeptrack.Domain.Models.ExploreCatalogueEntryModel.WebUrls"/>.
/// </para>
/// </summary>
public static class ProviderWebLinks
{
    /// <summary>A movie's page on themoviedb.org, from its TMDB id.</summary>
    public static string TmdbMovie(string tmdbId) => $"https://www.themoviedb.org/movie/{tmdbId}";

    /// <summary>A show's page on themoviedb.org, from its TMDB id. TMDB's own URL space splits movie and TV.</summary>
    public static string TmdbTvShow(string tmdbId) => $"https://www.themoviedb.org/tv/{tmdbId}";

    /// <summary>
    /// A title's page on imdb.com, from the IMDb id (<c>tt0111161</c>) TMDB exposes. IMDb has no ratings API
    /// (which is why OMDb exists here at all), but its *pages* are plain and stable on that id.
    /// </summary>
    public static string Imdb(string imdbId) => $"https://www.imdb.com/title/{imdbId}/";

    /// <summary>A game's page on rawg.io, from the slug RAWG returns beside every listing entry.</summary>
    public static string Rawg(string slug) => $"https://rawg.io/games/{slug}";
}
