using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.BlazorApp.Components.Inventory.Shared;
using Keeptrack.BlazorApp.Components.Shared;
using Keeptrack.WebApi.Contracts.Dto;
using Xunit;

namespace Keeptrack.BlazorApp.UnitTests.Components.Shared;

public partial class ChartsTest
{
    private static readonly List<ConsumptionPointDto> s_consumption =
    [
        new() { Date = new DateOnly(2025, 1, 10), ValuePer100Km = 6.4 },
        new() { Date = new DateOnly(2025, 3, 2), ValuePer100Km = 5.9 },
        new() { Date = new DateOnly(2025, 5, 20), ValuePer100Km = 7.1 }
    ];

    private static readonly List<CarCostHistoryPointDto> s_carCosts =
    [
        new() { Period = new DateOnly(2025, 1, 1), FuelCost = 120, MaintenanceCost = 0, TotalCost = 120 },
        new() { Period = new DateOnly(2025, 2, 1), FuelCost = 90.5, MaintenanceCost = 300, TotalCost = 390.5 }
    ];

    private static readonly List<HouseCostHistoryPointDto> s_houseCosts =
    [
        new() { Year = 2024, TotalCost = 1200, CostByCategory = [] },
        new() { Year = 2025, TotalCost = 1850.25, CostByCategory = [] }
    ];

    private static Task<string> RenderConsumptionAsync() =>
        HtmlRendering.RenderAsync<ConsumptionChart>(new Dictionary<string, object?>
        {
            [nameof(ConsumptionChart.Points)] = s_consumption,
            [nameof(ConsumptionChart.Color)] = "var(--kt-accent)",
            [nameof(ConsumptionChart.YAxisLabel)] = "L/100km",
            [nameof(ConsumptionChart.ChartId)] = "fuel",
            [nameof(ConsumptionChart.Geometry)] = SvgChartHelpers.HalfWidthGeometry
        });

    [GeneratedRegex("""\s(?:x|y|x1|y1|x2|y2|cx|cy|width|height)="-?\d+,\d""")]
    private static partial Regex DecimalCommaCoordinate();

    [GeneratedRegex("points=\"([^\"]*)\"")]
    private static partial Regex PolylinePoints();

    [GeneratedRegex("<rect ")]
    private static partial Regex RectTag();

    [Fact]
    public async Task ConsumptionChart_WritesCoordinatesWithADecimalPoint_UnderACultureWithADecimalComma()
    {
        var previous = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = new CultureInfo("fr-FR");
        try
        {
            var html = await RenderConsumptionAsync();

            DecimalCommaCoordinate().IsMatch(html).Should().BeFalse(html);
            PolylinePoints().Match(html).Groups[1].Value.Should().MatchRegex(@"^-?\d+\.\d,-?\d+\.\d( -?\d+\.\d,-?\d+\.\d)*$");
            html.Should().Contain("""viewBox="0 0 300 170""");
        }
        finally
        {
            CultureInfo.CurrentCulture = previous;
        }
    }

    [Fact]
    public async Task ConsumptionChart_DrawsOnePointPerReading_OnSharedAxes()
    {
        var html = await RenderConsumptionAsync();

        Regex.Matches(html, "<circle ").Should().HaveCount(s_consumption.Count);
        html.Should().Contain("<title>2025-03-02: 5.9</title>");
        html.Should().Contain("""marker id="kt-chart-arrow-fuel""");
        html.Should().Contain(">L/100km</text>").And.Contain(">Date</text>");
    }

    [Fact]
    public async Task CarCostHistoryChart_StacksFuelOnMaintenance_WithATooltipPerSegment()
    {
        var html = await HtmlRendering.RenderAsync<CarCostHistoryChart>(new Dictionary<string, object?> { [nameof(CarCostHistoryChart.Points)] = s_carCosts });

        RectTag().Matches(html).Should().HaveCount(s_carCosts.Count * 2);
        html.Should().Contain("<title>2025-02: maintenance 300.00</title>").And.Contain("<title>2025-02: fuel 90.50</title>");
        html.Should().Contain(">Month</text>").And.Contain(">&#x20AC;</text>", "the Y axis is captioned with the euro sign, which the HTML renderer encodes");
    }

    [Fact]
    public async Task HouseCostHistoryChart_LabelsEveryYear()
    {
        var html = await HtmlRendering.RenderAsync<HouseCostHistoryChart>(new Dictionary<string, object?> { [nameof(HouseCostHistoryChart.Points)] = s_houseCosts });

        RectTag().Matches(html).Should().HaveCount(s_houseCosts.Count);
        s_houseCosts.Select(p => $">{p.Year}</text>").Should().AllSatisfy(label => html.Should().Contain(label));
    }
}
