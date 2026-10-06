namespace Keeptrack.Domain.Models;

/// <summary>
/// One combination confirmed to mean a specific work, by automatic resolution or an admin's pick, embedded in its reference document.
/// Two tenants, or a tenant and the provider, can record different years for one work,
/// so the year travels with the title variant it was confirmed under (see <see cref="TvShowReferenceModel.MatchedAliases"/>).
/// <para>
/// <see cref="Domain.Services.ReferenceAliasRule"/> decides which members a domain's alias carries, and whether a combination identifies a work at all.
/// Nothing builds one for storage by hand.
/// </para>
/// </summary>
public class ReferenceMatchModel
{
    public required string Title { get; set; }

    public int? Year { get; set; }

    /// <summary>
    /// Normalized book author or album artist this combination was confirmed under, null for the domains without a creator.
    /// Books and albums need it: two different novels titled "Echoes" can share a year, and without the creator the second would link to the first's reference.
    /// The name is generic rather than "Author" or "Artist", since it serves both domains.
    /// </summary>
    public string? Creator { get; set; }

    /// <summary>
    /// The ISBN the match was made with, books only.
    /// Null when the match did not use an ISBN: an alias records only the identifier really used, never the provider's own ISBN.
    /// </summary>
    public string? Isbn { get; set; }

    /// <summary>
    /// Whether this alias is the combination the arguments describe: the single definition of "already recorded",
    /// shared by every path merging aliases (<c>MergeMatchedAliases</c> and the reference-data import).
    /// All four members take part, since a title and year mean a different work with another creator, and an ISBN match is a separate alias from a title match.
    /// <paramref name="title"/> and <paramref name="creator"/> arrive normalized, as aliases are stored, so this does no normalizing.
    /// A wrong comparison appends a duplicate alias on every re-resolve.
    /// </summary>
    public bool Matches(string title, int? year, string? creator, string? isbn) =>
        Title == title && Year == year && SameOptional(Creator, creator) && SameOptional(Isbn, isbn);

    /// <summary>
    /// Null and <c>""</c> are the same absence, since older documents store an absent creator as an empty string.
    /// Reading one as a different creator would append a duplicate on every re-resolve.
    /// </summary>
    private static bool SameOptional(string? recorded, string? candidate) =>
        string.IsNullOrEmpty(recorded) ? string.IsNullOrEmpty(candidate) : recorded == candidate;
}
