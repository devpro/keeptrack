namespace Keeptrack.Common.System;

/// <summary>
/// Shared title normalization for matching by name across the import pipeline and the reference-data
/// layer - one implementation so both never drift apart on what counts as "the same title".
/// </summary>
public static class TitleNormalizer
{
    public static string Normalize(string title) => title.Trim().ToLowerInvariant();
}
