namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// The single declaration of which rating sources a domain can pick a primary from, and the code default
/// when an admin hasn't chosen one. Only domains with more than one source are worth making selectable;
/// today that's just video games (RAWG vs Metacritic). When movies/TV gain a second source (IMDb, phase 2)
/// they get an entry here and reuse the same admin-selection + recompute mechanism with no other change.
/// Keeping defaults and available options in one place is what lets the enrichment service and the admin
/// endpoints agree without duplicating that knowledge.
/// </summary>
public static class RatingSourceCatalog
{
    /// <summary>RAWG's own 0-5 user score - the safer video-game default (usually present).</summary>
    public const string Rawg = "rawg";

    /// <summary>Metacritic's 0-100 critic score - frequently absent on RAWG for smaller/older games.</summary>
    public const string Metacritic = "metacritic";

    // per domain, the selectable source keys; the first is the code default.
    private static readonly IReadOnlyDictionary<ReferenceItemType, IReadOnlyList<string>> s_sources =
        new Dictionary<ReferenceItemType, IReadOnlyList<string>>
        {
            [ReferenceItemType.VideoGame] = [Rawg, Metacritic]
        };

    /// <summary>Domains whose primary rating source an admin can choose (those with more than one source).</summary>
    public static IReadOnlyList<ReferenceItemType> SelectableDomains => s_sources.Keys.ToList();

    /// <summary>Whether <paramref name="domain"/>'s primary rating source is admin-selectable.</summary>
    public static bool IsSelectable(ReferenceItemType domain) => s_sources.ContainsKey(domain);

    /// <summary>The selectable source keys for <paramref name="domain"/> (empty if not selectable).</summary>
    public static IReadOnlyList<string> AvailableSources(ReferenceItemType domain) =>
        s_sources.TryGetValue(domain, out var sources) ? sources : [];

    /// <summary>The code default source for <paramref name="domain"/> (used when no admin override is set).</summary>
    public static string DefaultSource(ReferenceItemType domain) =>
        AvailableSources(domain).FirstOrDefault()
        ?? throw new ArgumentOutOfRangeException(nameof(domain), $"No rating sources are declared for {domain}.");
}
