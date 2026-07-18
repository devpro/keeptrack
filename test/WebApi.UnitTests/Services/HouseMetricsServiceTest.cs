using System;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class HouseMetricsServiceTest
{
    private static HouseHistoryModel Entry(string id, DateOnly date, HouseEventType eventType, double? cost = null) =>
        new() { Id = id, OwnerId = "owner", HouseId = "house-1", HistoryDate = date, EventType = eventType, Cost = cost };

    [Fact]
    public void ComputeMetrics_CostHistory_IsEmpty_WhenThereIsNoHistory()
    {
        var result = HouseMetricsService.ComputeMetrics([]);

        result.CostHistory.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_CostHistory_ExcludesEntriesWithNoCost()
    {
        var history = new[] { Entry("h1", new DateOnly(2024, 3, 1), HouseEventType.Maintenance, cost: null) };

        var result = HouseMetricsService.ComputeMetrics(history);

        result.CostHistory.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_CostHistory_GroupsByYearAndSumsCost()
    {
        var history = new[]
        {
            Entry("h1", new DateOnly(2024, 1, 5), HouseEventType.Bill, cost: 60),
            Entry("h2", new DateOnly(2024, 6, 1), HouseEventType.Maintenance, cost: 150),
            Entry("h3", new DateOnly(2025, 2, 1), HouseEventType.Purchase, cost: 400)
        };

        var result = HouseMetricsService.ComputeMetrics(history);

        result.CostHistory.Should().HaveCount(2);
        var year2024 = result.CostHistory[0];
        year2024.Year.Should().Be(2024);
        year2024.TotalCost.Should().Be(210);

        var year2025 = result.CostHistory[1];
        year2025.Year.Should().Be(2025);
        year2025.TotalCost.Should().Be(400);
    }

    [Fact]
    public void ComputeMetrics_CostHistory_BreaksDownByCategoryWithinAYear()
    {
        var history = new[]
        {
            Entry("h1", new DateOnly(2024, 1, 5), HouseEventType.Bill, cost: 60),
            Entry("h2", new DateOnly(2024, 2, 5), HouseEventType.Bill, cost: 40),
            Entry("h3", new DateOnly(2024, 6, 1), HouseEventType.Maintenance, cost: 150)
        };

        var result = HouseMetricsService.ComputeMetrics(history);

        var year2024 = result.CostHistory.Should().ContainSingle().Subject;
        year2024.CostByCategory.Should().HaveCount(2);
        year2024.CostByCategory.Should().ContainSingle(c => c.EventType == HouseEventType.Bill && c.Cost == 100);
        year2024.CostByCategory.Should().ContainSingle(c => c.EventType == HouseEventType.Maintenance && c.Cost == 150);
    }

    [Fact]
    public void ComputeMetrics_LastRecords_GroupsByEventType_MostRecentFirst()
    {
        var history = new[]
        {
            Entry("h1", new DateOnly(2024, 1, 10), HouseEventType.Bill),
            Entry("h2", new DateOnly(2024, 3, 1), HouseEventType.Bill),
            Entry("h3", new DateOnly(2024, 2, 1), HouseEventType.Maintenance)
        };

        var result = HouseMetricsService.ComputeMetrics(history);

        result.LastRecords.Should().HaveCount(2);
        result.LastRecords[0].EventType.Should().Be(HouseEventType.Bill);
        result.LastRecords[0].LastDate.Should().Be(new DateOnly(2024, 3, 1));
        result.LastRecords[1].EventType.Should().Be(HouseEventType.Maintenance);
        result.LastRecords[1].LastDate.Should().Be(new DateOnly(2024, 2, 1));
    }
}
