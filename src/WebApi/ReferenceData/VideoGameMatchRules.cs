using Keeptrack.Common.System;

namespace Keeptrack.WebApi.ReferenceData;

/// <summary>
/// When a provider's candidate is the same game as the one being looked for, and what a requested year is
/// allowed to decide about it. One declaration, read by everything that has to answer either question:
/// <see cref="VideoGameReferenceClientBase"/> ranks a search's candidates with it, and
/// <c>ReferenceEnrichmentService</c> confirms automatic resolution and provider adoption with it - so what a
/// picker puts first and what links unattended can never drift apart.
/// <para>
/// <b>The year is not a tie-break in this domain, it is the identity.</b> Two genuinely different games sharing
/// a title is ordinary rather than exceptional here: IGDB holds eight games named exactly "Resident Evil 2"
/// (1998, 1999, 2019, 2024, 2025 and one undated) and seven named "Resident Evil". For every one of them the
/// title is no evidence at all about which is meant, and the year is the only thing that is.
/// </para>
/// </summary>
public static class VideoGameMatchRules
{
    /// <summary>The candidate is released in the year that was asked for - or none was asked for.</summary>
    public const int YearAgrees = 0;

    /// <summary>The provider reports no year for this candidate. Missing data, not a disagreement.</summary>
    public const int YearUnknown = 1;

    /// <summary>The candidate is released in a different year. A disagreement, and never a confirmation.</summary>
    public const int YearContradicts = 2;

    /// <summary>
    /// How well a candidate's year agrees with the one that was asked for, best first - the three states in
    /// this file's constants.
    /// <para>
    /// The middle rung is why this is not a boolean, and it is a measured distinction in both directions. Fold
    /// <see cref="YearUnknown"/> into <see cref="YearContradicts"/> and a provider that simply has no date for
    /// a game discards the right answer; fold it into <see cref="YearAgrees"/> and it counts as confirmation -
    /// which floated IGDB's undated "Resident Evil" above the 2002 remake for a search that plainly asked for
    /// 2002, and left the undated "Resident Evil 2" blocking automatic resolution of the 2019 one.
    /// </para>
    /// <para>
    /// With no year requested every candidate ranks <see cref="YearAgrees"/>, which is what leaves a caller
    /// that supplies none exactly where it was: relying on the title and the provider's own relevance order.
    /// </para>
    /// </summary>
    public static int YearRank(int? candidateYear, int? requestedYear) =>
        requestedYear is null || candidateYear == requestedYear ? YearAgrees
        : candidateYear is null ? YearUnknown
        : YearContradicts;

    /// <summary>
    /// Candidates ordered by how well they answer "is this <paramref name="title"/> (<paramref name="year"/>)",
    /// best first - a perfect match ahead of everything, then whatever is closest to what was asked for.
    /// <para>
    /// One ordering for every surface that shows a human a list of candidates: a provider search's five
    /// results, the admin reconciliation row, and the shortlist that unranked substring queries are cut down
    /// to. They were three separate opinions about the same question, of which only the reconciliation row's
    /// had been thought through, and a candidate list is exactly where an inconsistency wastes someone's time.
    /// </para>
    /// <para>
    /// The keys, in order. <b>Naming the work</b> comes first, so a perfect match cannot be displaced by
    /// anything - it is the answer, and every other candidate is at best a guess. <b>The year</b> is next,
    /// because among candidates that all name the work it is the only thing that identifies one (IGDB holds
    /// eight games named exactly "Resident Evil 2"). <b>Then title distance</b>, which is what orders the
    /// candidates that are not this work at all: an edition, a DLC pack or a bundle is spelled as the game plus
    /// something, so the shortest is the closest thing to what was asked for - measured on the real catalogue,
    /// this is what puts "Marvel's Avengers" ahead of the 40 crossovers and expansions containing both its
    /// words. The title breaks the last ties so the order is total, and therefore stable across identical
    /// requests.
    /// </para>
    /// </summary>
    public static IEnumerable<VideoGameSearchResult> OrderByBestMatch(IEnumerable<VideoGameSearchResult> candidates, string title, int? year)
    {
        var target = TitleNormalizer.NormalizeLoose(title).Length;
        return candidates
            .OrderBy(candidate => TitleNormalizer.LooselyEqual(candidate.Title, title) ? 0 : 1)
            .ThenBy(candidate => YearRank(candidate.Year, year))
            .ThenBy(candidate => Math.Abs(TitleNormalizer.NormalizeLoose(candidate.Title).Length - target))
            .ThenBy(candidate => candidate.Title, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The candidates that are confirmed to be <paramref name="title"/> (<paramref name="year"/>) - named the
    /// same work under <see cref="TitleNormalizer.LooselyEqual"/>, and agreeing about the year as well as any
    /// candidate does.
    /// <para>
    /// Callers act only on a *single* confirmed match and leave anything else for a human, so what this returns
    /// is a shortlist rather than a verdict: several means "don't guess", none means "nothing here is this
    /// game".
    /// </para>
    /// <para>
    /// <b>Only the best year tier that any candidate reaches is returned</b>, which is the whole point of
    /// asking for a year. A search for "Resident Evil 2" (2019) finds the 2019 game *and* an undated entry of
    /// the same name; keeping both would report an ambiguity the requested year has already resolved, and
    /// nothing further could ever resolve it - the undated entry has no year to be told apart by. A candidate
    /// whose year contradicts the request is never confirmed at all, however alone it is: that is the case
    /// where a title match is most likely to be a different game entirely (a remake, a same-named sequel), and
    /// linking it is the silent data loss this whole rule exists to avoid.
    /// </para>
    /// </summary>
    public static IReadOnlyList<VideoGameSearchResult> ConfirmedMatches(IEnumerable<VideoGameSearchResult> candidates, string title, int? year)
    {
        var named = candidates.Where(candidate => TitleNormalizer.LooselyEqual(candidate.Title, title)).ToList();
        if (named.Count == 0) return named;

        var best = named.Min(candidate => YearRank(candidate.Year, year));
        return best == YearContradicts ? [] : named.Where(candidate => YearRank(candidate.Year, year) == best).ToList();
    }
}
