using System.Globalization;
using ClosedXML.Excel;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// Cell parsing shared by the one-off Excel importers (<see cref="CarHistoryImportService"/>, <see cref="HealthImportService"/>).
/// </summary>
internal static class ExcelCellParser
{
    /// <summary>
    /// "Heure" cells are Excel times (a fraction of a day) or plain text ("11:57"), and <c>GetFormattedString()</c> renders both alike, so one text parse handles both.
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
    /// Euro amounts are often Excel formulas producing floating-point noise (36.049999999999997), so they are rounded to the cent.
    /// </summary>
    internal static double? PriceOrNull(IXLCell? cell) => DoubleOrNull(cell) is { } value ? Math.Round(value, 2) : null;

    internal static int? IntOrNull(IXLCell? cell) => DoubleOrNull(cell) is { } value ? (int)Math.Round(value) : null;

    internal static string? JoinNonEmpty(string separator, params string?[] parts)
    {
        var joined = string.Join(separator, parts.Where(p => !string.IsNullOrWhiteSpace(p)));
        return joined.Length > 0 ? joined : null;
    }
}
