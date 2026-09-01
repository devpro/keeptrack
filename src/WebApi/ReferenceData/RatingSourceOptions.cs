using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// Which rating sources a domain offers an admin, and which one is effective given the stored choice.
/// <para>
/// An injected service rather than a static table because the video game answer is a <b>deployment</b> fact,
/// not a compile-time one: the sources that domain can offer are exactly the ones its registered default
/// provider reports (<see cref="IVideoGameReferenceClient.SupportedRatingSources"/>), so setting
/// <c>ReferenceData:VideoGameProvider</c> back to RAWG makes <c>rawg</c>/<c>metacritic</c> selectable again,
/// and IGDB's two scores stop being offered - with no code change and no migration.
/// Same reason <see cref="ExploreRankings"/> is injected.
/// </para>
/// <para>
/// This replaces a hardcoded per-domain list, which had the failure mode both ways round. It offered
/// Metacritic long after IGDB became the default although IGDB cannot produce it, so every game linked since
/// the switch resolved to no rating at all; and it would equally have kept offering IGDB's scores on a
/// deployment that had gone back to RAWG. <b>A source no registered provider can produce must not be
/// selectable, and one it can must not stay hidden.</b>
/// </para>
/// <para>
/// A stored override that isn't currently available is <b>ignored, never erased</b> (see <see cref="Resolve"/>),
/// which is what makes a provider change reversible: an admin who chose Metacritic under RAWG falls back to
/// the current default while IGDB is in charge, and gets their choice back untouched the moment RAWG is.
/// </para>
/// </summary>
public class RatingSourceOptions(ReferenceClientRegistry<IVideoGameReferenceClient> videoGameClients)
{
    /// <summary>
    /// The domains whose sources are fixed because the domain has exactly one provider - TMDB for movies and
    /// TV, whose second source (IMDb, via OMDb) is not a provider swap but an extra lookup on top of it.
    /// The first entry is the code default. Video games are deliberately absent: their answer comes from
    /// whichever client is registered as the default.
    /// </summary>
    private static readonly IReadOnlyDictionary<ReferenceItemType, IReadOnlyList<string>> s_fixedSources =
        new Dictionary<ReferenceItemType, IReadOnlyList<string>>
        {
            [ReferenceItemType.Movie] = [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb],
            [ReferenceItemType.TvShow] = [RatingSourceCatalog.Tmdb, RatingSourceCatalog.Imdb]
        };

    /// <summary>Domains whose primary rating source an admin can choose (those offering more than one).</summary>
    public IReadOnlyList<ReferenceItemType> SelectableDomains =>
        [.. s_fixedSources.Keys, ReferenceItemType.VideoGame];

    /// <summary>Whether <paramref name="domain"/>'s primary rating source is admin-selectable.</summary>
    public bool IsSelectable(ReferenceItemType domain) => AvailableSources(domain).Count > 1;

    /// <summary>
    /// The source keys <paramref name="domain"/> currently offers, in priority order (empty if it offers no
    /// choice at all - books read whichever provider key their reference happens to store).
    /// </summary>
    public IReadOnlyList<string> AvailableSources(ReferenceItemType domain) => domain switch
    {
        ReferenceItemType.VideoGame => videoGameClients.Resolve(null).SupportedRatingSources,
        _ => s_fixedSources.TryGetValue(domain, out var sources) ? sources : []
    };

    /// <summary>The code default for <paramref name="domain"/> - the first source it offers - used when no admin override applies.</summary>
    public string DefaultSource(ReferenceItemType domain) =>
        AvailableSources(domain).FirstOrDefault()
        ?? throw new ArgumentOutOfRangeException(nameof(domain), $"No rating sources are available for {domain}.");

    /// <summary>
    /// The effective primary source for <paramref name="domain"/>: the admin's stored choice while it names a
    /// source currently on offer, otherwise the code default. The single resolver shared by
    /// <c>ReferenceEnrichmentService.GetPrimaryRatingSourceAsync</c> and the Explore feature.
    /// </summary>
    public string Resolve(IReadOnlyDictionary<string, string> overrides, ReferenceItemType domain) =>
        overrides.TryGetValue(domain.ToString(), out var stored) && AvailableSources(domain).Contains(stored)
            ? stored
            : DefaultSource(domain);
}
