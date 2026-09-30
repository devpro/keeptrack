using System.Globalization;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Geometry and formatting shared by the hand-rolled SVG charts, which draw their axes through <c>ChartAxes.razor</c>.
/// There is no charting library for a handful of small charts.
/// Each chart keeps its own series drawing, which differs too much between a line, a bar and a stacked bar to share one renderer.
/// </summary>
public static class SvgChartHelpers
{
    /// <summary>
    /// Plot geometry for one chart.
    /// A full-width chart has a proportionally wider viewBox than a half-width one, so axis text, arrows and ticks render at the same size in both.
    /// </summary>
    public readonly record struct ChartGeometry(
        double ViewWidth,
        double ViewHeight,
        double PlotLeft,
        double PlotRight,
        double PlotTop,
        double PlotBottom);

    public static readonly ChartGeometry HalfWidthGeometry =
        new(ViewWidth: 300, ViewHeight: 170, PlotLeft: 40, PlotRight: 288, PlotTop: 14, PlotBottom: 132);

    public static readonly ChartGeometry FullWidthGeometry =
        new(ViewWidth: 600, ViewHeight: 170, PlotLeft: 40, PlotRight: 588, PlotTop: 14, PlotBottom: 132);

    /// <summary>
    /// Formats an SVG coordinate or length.
    /// Always the invariant culture, since a host running under a culture with a decimal comma would otherwise write "40,0" and break every chart.
    /// </summary>
    public static string ToSvg(double value) => value.ToString("F1", CultureInfo.InvariantCulture);

    /// <summary>Formats a <c>viewBox</c> dimension, which carries no fixed decimal places.</summary>
    public static string ToSvgDimension(double value) => value.ToString(CultureInfo.InvariantCulture);

    /// <summary>
    /// Picks up to <paramref name="count"/> evenly spaced indices from a 0-based range, always including the first and last, for X-axis ticks.
    /// </summary>
    public static List<int> EvenlySpacedIndices(int total, int count)
    {
        if (total <= 1 || count <= 1) return [0];
        count = Math.Min(count, total);
        return Enumerable.Range(0, count)
            .Select(i => i * (total - 1) / (count - 1))
            .Distinct()
            .ToList();
    }
}
