using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// One page of Explore suggestions, plus the cursor to continue from.
/// </summary>
public class ExploreSuggestionPageDto
{
    /// <summary>The suggestions in this page, in the provider ranking's own order.</summary>
    public List<ExploreSuggestionDto> Items { get; set; } = [];

    /// <summary>
    /// Pass back as <c>after</c> to fetch the next page; null once the ranking is exhausted, which is what a
    /// client uses to stop offering "load more".
    /// <para>
    /// A rank cursor rather than a page number because the per-caller exclusions ("already tracked",
    /// "dismissed") are applied after the ranked read: a skip/limit page would shift under the client and
    /// silently drop suggestions as titles are filtered out. A page may therefore hold fewer than the
    /// requested count and still have more to come.
    /// </para>
    /// </summary>
    public int? NextCursor { get; set; }

    /// <summary>
    /// True when this domain's ranking hasn't been built yet (a fresh deployment, before the first periodic
    /// refresh pass) rather than the caller having run out of suggestions. Both are an empty list, but they
    /// mean opposite things to a user - "check back shortly" versus "you already track them all".
    /// </summary>
    public bool CataloguePending { get; set; }
}
