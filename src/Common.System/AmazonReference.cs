using System;
using System.Text.RegularExpressions;

namespace Keeptrack.Common.System;

/// <summary>
/// The read side of an Amazon-imported owned copy's <c>Reference</c> text (written by
/// <c>AmazonImportMergeService.FormatOrderReference</c> in the Domain project as
/// <c>"Amazon order {orderId} (ASIN {asin})"</c>). Lives here, not next to the writer, because it also
/// needs to be callable from BlazorApp (which can't reference Domain) to build an "open on Amazon" link -
/// keeping both halves of the same string shape in one place avoids the two drifting apart independently.
/// </summary>
public static partial class AmazonReference
{
    [GeneratedRegex(@"\(ASIN\s+([A-Za-z0-9]{10})\)")]
    private static partial Regex AsinPattern();

    /// <summary>
    /// The ASIN embedded in an owned copy's <c>Reference</c> text, or null when it isn't there (most
    /// copies weren't imported from Amazon at all).
    /// </summary>
    public static string? TryExtractAsin(string? reference)
    {
        if (string.IsNullOrEmpty(reference))
        {
            return null;
        }

        var match = AsinPattern().Match(reference);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// Amazon's own permalink shape (works on any of its marketplaces). <paramref name="vendor"/> is the
    /// owned copy's own Vendor field - for an Amazon-imported copy this is the CSV export's "Website"
    /// column (e.g. "Amazon.fr"), so a mixed-marketplace order history still opens on the right site
    /// instead of always guessing one locale. Falls back to amazon.fr when the vendor isn't recognizably
    /// an Amazon domain (a manually-entered copy, or an older import that didn't carry one).
    /// </summary>
    public static string BuildProductUrl(string asin, string? vendor) => $"https://{TryGetAmazonDomain(vendor) ?? "www.amazon.fr"}/dp/{asin}";

    private static string? TryGetAmazonDomain(string? vendor)
    {
        var trimmed = vendor?.Trim();
        if (string.IsNullOrEmpty(trimmed) || !trimmed.Contains("amazon", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var withoutScheme = SchemePrefix().Replace(trimmed, "");
        return withoutScheme.Split('/')[0].ToLowerInvariant();
    }

    [GeneratedRegex(@"^https?://", RegexOptions.IgnoreCase)]
    private static partial Regex SchemePrefix();
}
