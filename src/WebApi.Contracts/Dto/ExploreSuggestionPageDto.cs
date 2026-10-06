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
    /// Passed back as <c>after</c> for the next page, and null once the ranking is exhausted, so the client stops offering "load more".
    /// <para>
    /// A rank cursor rather than a page number, since the caller's exclusions (tracked, dismissed) apply after the ranked read,
    /// and a skip and limit page would shift and drop suggestions.
    /// A page can therefore hold fewer than requested and still have more to come.
    /// </para>
    /// </summary>
    public int? NextCursor { get; set; }

    /// <summary>
    /// True when this domain's ranking is not built yet, before the first refresh of a new deployment, rather than the caller having seen every suggestion.
    /// Both are an empty list, but one means "check back shortly" and the other "everything is already tracked".
    /// </summary>
    public bool CataloguePending { get; set; }
}
