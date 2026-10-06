using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Which rating sources a domain offers an admin, and which one is effective given the stored choice.
/// <para>
/// An injected service rather than a static table, since the video game answer is a deployment fact.
/// The domain offers the sources its default provider reports (<see cref="IVideoGameReferenceClient.SupportedRatingSources"/>), so switching <c>ReferenceData:VideoGameProvider</c> needs no code or migration, as for <see cref="ExploreRankings"/>.
/// </para>
/// <para>
/// <b>A source no registered provider produces is never selectable, and one it produces never stays hidden.</b>
/// A fixed list would offer Metacritic under IGDB, which cannot produce it, leaving every game linked since without a rating.
/// </para>
/// <para>
/// A stored choice not currently on offer is <b>ignored, never erased</b> (see <see cref="Resolve"/>), which makes a provider change reversible: a Metacritic choice made under RAWG returns as soon as RAWG does.
/// </para>
/// </summary>
public class RatingSourceOptions(ReferenceClientRegistry<IVideoGameReferenceClient> videoGameClients)
{
    /// <summary>
    /// The domains with fixed sources, having one provider: TMDB for movies and TV, IMDb being an extra lookup through OMDb rather than another provider.
    /// The first entry is the default.
    /// Video games are absent, their answer coming from the default client.
    /// </summary>
    private static readonly IReadOnlyDictionary<ReferenceItemType, IReadOnlyList<string>> s_fixedSources =
        new Dictionary<ReferenceItemType, IReadOnlyList<string>>
        {
            [ReferenceItemType.Movie] = [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb],
            [ReferenceItemType.TvShow] = [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb]
        };

    /// <summary>Domains whose primary rating source an admin can choose, those offering more than one.</summary>
    public IReadOnlyList<ReferenceItemType> SelectableDomains =>
        [.. s_fixedSources.Keys, ReferenceItemType.VideoGame];

    /// <summary>Whether <paramref name="domain"/>'s primary rating source is admin-selectable.</summary>
    public bool IsSelectable(ReferenceItemType domain) => AvailableSources(domain).Count > 1;

    /// <summary>
    /// The source keys <paramref name="domain"/> offers, in priority order, or none, since books read whichever key their reference stores.
    /// </summary>
    public IReadOnlyList<string> AvailableSources(ReferenceItemType domain) => domain switch
    {
        ReferenceItemType.VideoGame => videoGameClients.Resolve(null).SupportedRatingSources,
        _ => s_fixedSources.TryGetValue(domain, out var sources) ? sources : []
    };

    /// <summary>The default of <paramref name="domain"/>, its first source, used when no admin choice applies.</summary>
    public string DefaultSource(ReferenceItemType domain) =>
        AvailableSources(domain).FirstOrDefault()
        ?? throw new ArgumentOutOfRangeException(nameof(domain), $"No rating sources are available for {domain}.");

    /// <summary>
    /// The effective primary source of <paramref name="domain"/>: the admin's choice while on offer, else the default.
    /// Shared by <c>ReferenceEnrichmentService.GetPrimaryRatingSourceAsync</c> and Explore.
    /// </summary>
    public string Resolve(IReadOnlyDictionary<string, string> overrides, ReferenceItemType domain) =>
        overrides.TryGetValue(domain.ToString(), out var stored) && AvailableSources(domain).Contains(stored)
            ? stored
            : DefaultSource(domain);
}
