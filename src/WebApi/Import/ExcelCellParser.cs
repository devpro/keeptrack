using System.Globalization;
using ClosedXML.Excel;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Cell-parsing helpers shared by the one-off Excel importers (<see cref="CarHistoryImportService"/>, <see cref="HealthImportService"/>) -
/// extracted rather than duplicated per importer.
/// </summary>
internal static class ExcelCellParser
{
    /// <summary>
    /// "Heure" columns are inconsistent in these personal files - some cells are real Excel time values (a fraction of a day), others plain text like "11:57" -
    /// but <c>GetFormattedString()</c> renders both the same way, so a single text parse handles both.
    /// </summary>
    internal static TimeOnly? ParseTime(IXLCell? cell)
    {
        if (cell is null || cell.IsEmpty()) return null;
        var text = cell.GetFormattedString().Trim();
        return TimeOnly.TryParse(text, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
    }

    internal static string? StringOrNull(IXLCell? cell)
    {
        if (cell is null || cell.IsEmpty()) return null;
        var text = cell.GetString().Trim();
        return text.Length > 0 ? text : null;
    }

    internal static double? DoubleOrNull(IXLCell? cell) => cell is not null && !cell.IsEmpty() && cell.TryGetValue(out double value) ? value : null;

    /// <summary>
    /// Euro-amount columns are often Excel formulas (sums of several acts), which routinely produce floating-point noise like 36.049999999999997 -
    /// rounded to the cent so every imported price is a real, displayable amount.
    /// </summary>
    internal static double? PriceOrNull(IXLCell? cell) => DoubleOrNull(cell) is { } value ? Math.Round(value, 2) : null;

    internal static int? IntOrNull(IXLCell? cell) => DoubleOrNull(cell) is { } value ? (int)Math.Round(value) : null;

    internal static string? JoinNonEmpty(string separator, params string?[] parts)
    {
        var joined = string.Join(separator, parts.Where(p => !string.IsNullOrWhiteSpace(p)));
        return joined.Length > 0 ? joined : null;
    }
}
