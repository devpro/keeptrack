using Microsoft.AspNetCore.Components.Rendering;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Shared SVG axis-drawing primitives for the app's hand-rolled charts (no charting library dependency for a handful of small trend/bar charts).
/// Extracted from <c>CarDetail.razor</c> so <c>HouseDetail.razor</c>'s own yearly cost chart doesn't duplicate the same axis geometry/arrow-marker/tick-label algorithm.
/// Deliberately limited to just axis/geometry, not the per-chart series-drawing code (line vs. bar, single vs. stacked series) -
/// that part differs enough between consumers that it stays with each page rather than being forced into one over-generalized shared renderer.
/// </summary>
public static class SvgChartHelpers
{
    /// <summary>
    /// Plot geometry for one chart.
    /// Not every chart shares a single fixed viewBox: a chart rendered at full row width needs a proportionally wider viewBox than a half-width one -
    /// matching ViewWidth to actual on-screen width keeps the rendered scale (and therefore axis text/arrow/tick size) the same across every chart instead of the wider ones blowing up.
    /// </summary>
    public readonly record struct ChartGeometry(double ViewWidth, double ViewHeight, double PlotLeft, double PlotRight, double PlotTop, double PlotBottom);

    public static readonly ChartGeometry HalfWidthGeometry = new(ViewWidth: 300, ViewHeight: 170, PlotLeft: 40, PlotRight: 288, PlotTop: 14, PlotBottom: 132);
    public static readonly ChartGeometry FullWidthGeometry = new(ViewWidth: 600, ViewHeight: 170, PlotLeft: 40, PlotRight: 588, PlotTop: 14, PlotBottom: 132);

    /// <summary>
    /// Draws a graduated X/Y axis pair (arrowhead, tick marks, tick labels, axis title).
    /// Ticks are computed by the caller, since what counts as an evenly-spaced value differs between a continuous line chart and a per-bar categorical one.
    /// The Y-axis title is a plain horizontal caption above the axis rather than rotated sideways along it -
    /// fine for a multi-word label like "L/100km", but a rotated single glyph like "€" reads as a completely different, garbled character, not a sideways euro sign.
    /// </summary>
#pragma warning disable ASP0006
    public static void RenderAxes(
        RenderTreeBuilder builder, ref int seq, ChartGeometry geometry, string markerId, string xAxisLabel, string yAxisLabel,
        IReadOnlyList<(double Y, string Label)> yTicks, IReadOnlyList<(double X, string Label)> xTicks)
    {
        const string AxisColor = "var(--kt-text-muted)";
        var (_, viewHeight, plotLeft, plotRight, plotTop, plotBottom) = geometry;

        builder.OpenElement(seq++, "defs");
        builder.OpenElement(seq++, "marker");
        builder.AddAttribute(seq++, "id", markerId);
        builder.AddAttribute(seq++, "viewBox", "0 0 8 8");
        builder.AddAttribute(seq++, "refX", "6");
        builder.AddAttribute(seq++, "refY", "4");
        builder.AddAttribute(seq++, "markerWidth", "6");
        builder.AddAttribute(seq++, "markerHeight", "6");
        builder.AddAttribute(seq++, "orient", "auto-start-reverse");
        builder.OpenElement(seq++, "path");
        builder.AddAttribute(seq++, "d", "M0,0 L8,4 L0,8 Z");
        builder.AddAttribute(seq++, "fill", AxisColor);
        builder.CloseElement();
        builder.CloseElement();
        builder.CloseElement();

        // Y-axis: drawn bottom-to-top so the arrowhead (marker-end) points up.
        builder.OpenElement(seq++, "line");
        builder.AddAttribute(seq++, "x1", plotLeft.ToString("F1"));
        builder.AddAttribute(seq++, "y1", plotBottom.ToString("F1"));
        builder.AddAttribute(seq++, "x2", plotLeft.ToString("F1"));
        builder.AddAttribute(seq++, "y2", plotTop.ToString("F1"));
        builder.AddAttribute(seq++, "stroke", AxisColor);
        builder.AddAttribute(seq++, "stroke-width", "1");
        builder.AddAttribute(seq++, "vector-effect", "non-scaling-stroke");
        builder.AddAttribute(seq++, "marker-end", $"url(#{markerId})");
        builder.CloseElement();

        // X-axis: drawn left-to-right so the arrowhead points right.
        builder.OpenElement(seq++, "line");
        builder.AddAttribute(seq++, "x1", plotLeft.ToString("F1"));
        builder.AddAttribute(seq++, "y1", plotBottom.ToString("F1"));
        builder.AddAttribute(seq++, "x2", plotRight.ToString("F1"));
        builder.AddAttribute(seq++, "y2", plotBottom.ToString("F1"));
        builder.AddAttribute(seq++, "stroke", AxisColor);
        builder.AddAttribute(seq++, "stroke-width", "1");
        builder.AddAttribute(seq++, "vector-effect", "non-scaling-stroke");
        builder.AddAttribute(seq++, "marker-end", $"url(#{markerId})");
        builder.CloseElement();

        foreach (var (y, label) in yTicks)
        {
            builder.OpenElement(seq++, "line");
            builder.AddAttribute(seq++, "x1", (plotLeft - 3).ToString("F1"));
            builder.AddAttribute(seq++, "y1", y.ToString("F1"));
            builder.AddAttribute(seq++, "x2", plotLeft.ToString("F1"));
            builder.AddAttribute(seq++, "y2", y.ToString("F1"));
            builder.AddAttribute(seq++, "stroke", AxisColor);
            builder.AddAttribute(seq++, "stroke-width", "1");
            builder.AddAttribute(seq++, "vector-effect", "non-scaling-stroke");
            builder.CloseElement();

            builder.OpenElement(seq++, "text");
            builder.AddAttribute(seq++, "x", (plotLeft - 5).ToString("F1"));
            builder.AddAttribute(seq++, "y", (y + 2.5).ToString("F1"));
            builder.AddAttribute(seq++, "text-anchor", "end");
            builder.AddAttribute(seq++, "class", "kt-chart-axis-text");
            builder.AddContent(seq++, label);
            builder.CloseElement();
        }

        foreach (var (x, label) in xTicks)
        {
            builder.OpenElement(seq++, "line");
            builder.AddAttribute(seq++, "x1", x.ToString("F1"));
            builder.AddAttribute(seq++, "y1", plotBottom.ToString("F1"));
            builder.AddAttribute(seq++, "x2", x.ToString("F1"));
            builder.AddAttribute(seq++, "y2", (plotBottom + 3).ToString("F1"));
            builder.AddAttribute(seq++, "stroke", AxisColor);
            builder.AddAttribute(seq++, "stroke-width", "1");
            builder.AddAttribute(seq++, "vector-effect", "non-scaling-stroke");
            builder.CloseElement();

            builder.OpenElement(seq++, "text");
            builder.AddAttribute(seq++, "x", x.ToString("F1"));
            builder.AddAttribute(seq++, "y", (plotBottom + 12).ToString("F1"));
            builder.AddAttribute(seq++, "text-anchor", "middle");
            builder.AddAttribute(seq++, "class", "kt-chart-axis-text");
            builder.AddContent(seq++, label);
            builder.CloseElement();
        }

        // Y-axis title: a plain horizontal caption in the top-left corner, naming the axis unit.
        builder.OpenElement(seq++, "text");
        builder.AddAttribute(seq++, "x", "2");
        builder.AddAttribute(seq++, "y", (plotTop - 4).ToString("F1"));
        builder.AddAttribute(seq++, "text-anchor", "start");
        builder.AddAttribute(seq++, "class", "kt-chart-axis-title");
        builder.AddContent(seq++, yAxisLabel);
        builder.CloseElement();

        var xTitleCenter = (plotLeft + plotRight) / 2;
        builder.OpenElement(seq++, "text");
        builder.AddAttribute(seq++, "x", xTitleCenter.ToString("F1"));
        builder.AddAttribute(seq++, "y", (viewHeight - 4).ToString("F1"));
        builder.AddAttribute(seq++, "text-anchor", "middle");
        builder.AddAttribute(seq++, "class", "kt-chart-axis-title");
        builder.AddContent(seq++, xAxisLabel);
        builder.CloseElement();
    }
#pragma warning restore ASP0006
    
    /// <summary>
    /// Picks up to <paramref name="count"/> evenly-spaced indices from a 0-based range, always including the first and last -
    /// shared by every chart's X-axis tick placement.
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
