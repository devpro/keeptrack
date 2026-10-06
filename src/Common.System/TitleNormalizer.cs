using System;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Keeptrack.Common.System;

/// <summary>
/// Title normalization for matching by name, shared by the imports and reference data so both agree on what counts as "the same title".
/// </summary>
public static class TitleNormalizer
{
    public static string Normalize(string title) => title.Trim().ToLowerInvariant();

    /// <summary>
    /// A looser form of <see cref="Normalize"/>, for matching one provider's title against another's.
    /// It folds diacritics, drops a <c>(1997)</c>-style disambiguator, removes punctuation and the article "the", and collapses whitespace.
    /// <para>
    /// Two catalogues name the same work differently in small, systematic ways, as real RAWG and IGDB records show.
    /// <c>Mass Effect: Legendary Edition</c> and <c>Mass Effect Legendary Edition</c> are one game, and so are <c>Disco Elysium: Final Cut</c> and <c>Disco Elysium: The Final Cut</c>.
    /// RAWG also disambiguates a remake by appending the original's year (<c>GoldenEye 007 (1997)</c>, <c>Resident Evil 2 (1998)</c>).
    /// Exact equality rejects every one of those, so the references cannot adopt the default provider's id, and Explore keeps suggesting games the user already has.
    /// </para>
    /// <para>
    /// It never replaces <see cref="Normalize"/> nor becomes the stored <c>TitleNormalized</c> or alias key.
    /// Those are matched against text a tenant typed, where losing this much information would conflate different items.
    /// Loose matching only shortlists candidates: every caller still confirms a compatible year and refuses anything but a single match.
    /// A false pairing therefore costs an entry in the admin reconciliation queue, not a wrong link.
    /// </para>
    /// <para>
    /// Roman numerals are left alone, so <c>Final Fantasy IV</c> stays distinct from <c>Final Fantasy 4</c>.
    /// The rule would be ambiguous for one-letter tokens, and an unmatched pair costs an admin one click where a wrong pair is silent data loss.
    /// </para>
    /// </summary>
    public static string NormalizeLoose(string title)
    {
        var folded = RemoveDiacritics(title).ToLowerInvariant();
        var builder = new StringBuilder(folded.Length);
        var depth = 0;

        foreach (var character in folded)
        {
            // a parenthesised group is dropped whole: it is a provider's disambiguator ("(1997)", "(remake)"), never part of the name people search with
            if (character is '(' or '[')
            {
                depth++;
                builder.Append(' ');
                continue;
            }
            if (character is ')' or ']')
            {
                if (depth > 0) depth--;
                continue;
            }
            if (depth > 0) continue;

            if (char.IsLetterOrDigit(character))
            {
                builder.Append(character);
            }
            else if (character is '\'' or '’')
            {
                // an apostrophe is dropped rather than turned into a space, so "Assassin's Creed" and "Assassins Creed" tokenize the same way.
                // A space would give "assassin s creed", which matches neither spelling.
                continue;
            }
            else
            {
                // "&" and every separator collapse to a single space, so "Rock & Roll", "Rock and Roll" and "Rock: Roll" all tokenize the same way
                builder.Append(character == '&' ? " and " : " ");
            }
        }

        return string.Join(' ', builder.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(token => token != "the"));
    }

    /// <summary>
    /// The title with any parenthesised or bracketed group removed and nothing else touched.
    /// Case, punctuation and accents are preserved, so the result is still a title a provider could hold verbatim.
    /// <para>
    /// <see cref="NormalizeLoose"/> only helps once candidates are in hand, and this is for asking the provider in the first place.
    /// RAWG puts the original's year in a remake's title (<c>GoldenEye 007 (1997)</c>, <c>God of War (2018)</c>, <c>Demon's Souls (2020)</c>).
    /// IGDB returns nothing at all for that string, from its exact-name lookup and from its relevance search, so there are no candidates for a looser comparison to rescue.
    /// Retrying with the bare title turns that dead end into an ordinary match.
    /// </para>
    /// </summary>
    public static string StripDisambiguator(string title)
    {
        var stripped = new StringBuilder(title.Length);
        var depth = 0;

        foreach (var character in title)
        {
            if (character is '(' or '[') depth++;
            else if (character is ')' or ']') { if (depth > 0) depth--; }
            else if (depth == 0) stripped.Append(character);
        }

        return string.Join(' ', stripped.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// The title reduced to plain words a provider's search can parse: diacritics folded, apostrophes dropped, and every other non-alphanumeric run collapsed to a single space.
    /// Unlike <see cref="NormalizeLoose"/> it keeps every word, "the" included, and the original casing, because the result is a query, not a matching key.
    /// <para>
    /// A provider's free-text search is far less forgiving about punctuation than its catalogue.
    /// IGDB answers <c>search "NieR:Automata"</c>, spelled as RAWG spells it, with only "Untitled NieR:Automata Project", while <c>search "NieR Automata"</c> returns the game as the top hit.
    /// The same form rescues a title carrying <c>!</c>, <c>,</c> or an accent.
    /// </para>
    /// <para>
    /// Asking with this form is safe because confirmation does not loosen.
    /// The candidates it brings back are still checked against the reference's own title with <see cref="LooselyEqual"/> and a compatible year, and anything but a single match is left for a human.
    /// </para>
    /// </summary>
    public static string ToProviderQuery(string title)
    {
        var folded = RemoveDiacritics(title);
        var builder = new StringBuilder(folded.Length);

        foreach (var character in folded)
        {
            if (character is '\'' or '’') continue;
            builder.Append(char.IsLetterOrDigit(character) ? character : ' ');
        }

        return string.Join(' ', builder.ToString().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>
    /// Whether two provider titles name the same work under <see cref="NormalizeLoose"/>.
    /// The comparison is written once, so adoption, the duplicate finder and the Explore exclusion agree on what "the same title" means.
    /// </summary>
    public static bool LooselyEqual(string left, string right) =>
        NormalizeLoose(left) == NormalizeLoose(right);

    /// <summary>
    /// Whether <paramref name="candidate"/> contains <paramref name="searched"/> as a whole run of words, under <see cref="NormalizeLoose"/>.
    /// Weaker than <see cref="LooselyEqual"/> on purpose: it answers whether the searched title appears in this result's title.
    /// That tells a genuine candidate ("Nevermind (Demo &amp; Outtakes)" for "Nevermind") from a result the provider returned for another reason.
    /// <para>
    /// A provider's free-text parameter also matches fields other than the title.
    /// Discogs answers <c>q=Discovery&amp;artist=Daft Punk</c> with "Live @ Rex Club, Paris" and "MP3 Collection" alongside the album, and <c>q=Sabbath</c> with releases naming the word only in the artist.
    /// See <c>DiscogsClient.SearchAlbumsCoreAsync</c>.
    /// </para>
    /// <para>
    /// It compares whole words rather than raw substrings, so a search for "Blue" does not keep a "Blueprint".
    /// A title that normalizes to nothing matches everything, rather than filtering the caller's results down to none.
    /// </para>
    /// </summary>
    public static bool LooselyContains(string candidate, string searched)
    {
        var searchedWords = NormalizeLoose(searched).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (searchedWords.Length == 0) return true;

        var candidateWords = NormalizeLoose(candidate).Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return Enumerable.Range(0, Math.Max(0, candidateWords.Length - searchedWords.Length + 1))
            .Any(start => candidateWords.Skip(start).Take(searchedWords.Length).SequenceEqual(searchedWords));
    }

    /// <summary>
    /// Strips combining marks so "Pokémon" and "Pokemon" compare equal, since catalogues disagree about accents.
    /// </summary>
    private static string RemoveDiacritics(string value)
    {
        var decomposed = value.Trim().Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(decomposed.Length);

        foreach (var character in decomposed.Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark))
        {
            builder.Append(character);
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }
}
