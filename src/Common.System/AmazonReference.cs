using System;
using System.Text.RegularExpressions;

namespace Keeptrack.Common.System;

/// <summary>
/// Reads back the <c>Reference</c> text of an owned copy imported from Amazon,
/// which <c>AmazonImportMergeService.FormatOrderReference</c> writes as <c>"Amazon order {orderId} (ASIN {asin})"</c>.
/// It lives here rather than next to the writer because BlazorApp, which cannot reference Domain, builds the "open on Amazon" link from it.
/// </summary>
public static partial class AmazonReference
{
    [GeneratedRegex(@"\(ASIN\s+([A-Za-z0-9]{10})\)")]
    private static partial Regex AsinPattern();

    /// <summary>
    /// The ASIN embedded in an owned copy's <c>Reference</c> text, or null when there is none, as for most copies.
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
    /// Amazon's permalink shape, which works on any of its marketplaces.
    /// <paramref name="vendor"/> is the copy's Vendor, which the import fills from the export's "Website" column (such as "Amazon.fr").
    /// An order history spanning several marketplaces therefore opens each product on its own site.
    /// A vendor that is not an Amazon domain, such as a copy entered by hand, falls back to amazon.fr.
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
