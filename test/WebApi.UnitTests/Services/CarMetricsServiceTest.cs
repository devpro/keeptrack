using System;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class CarMetricsServiceTest
{
    private static CarHistoryModel Refuel(
        string id, DateTime date, int mileage,
        double? fuelVolume = null, double? electricVolume = null, bool isFullRefill = true,
        double? deltaMileage = null, double? cost = null) =>
        new()
        {
            Id = id,
            OwnerId = "owner",
            CarId = "car-1",
            HistoryDate = date,
            Mileage = mileage,
            EventType = CarHistoryType.Refuel,
            FuelVolume = fuelVolume,
            ElectricVolume = electricVolume,
            IsFullRefill = isFullRefill,
            DeltaMileage = deltaMileage,
            Cost = cost
        };

    private static CarHistoryModel Maintenance(string id, DateTime date, int? mileage = null, double? cost = null) =>
        new()
        {
            Id = id,
            OwnerId = "owner",
            CarId = "car-1",
            HistoryDate = date,
            Mileage = mileage,
            EventType = CarHistoryType.Maintenance,
            Cost = cost
        };

    [Fact]
    public void ComputeMetrics_FuelConsumption_OnlyEmitsAPointAcrossAFullRefill()
    {
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40, isFullRefill: true),
            Refuel("h2", new DateTime(2024, 1, 15), 1200, fuelVolume: 20, isFullRefill: false),
            Refuel("h3", new DateTime(2024, 2, 1), 1400, fuelVolume: 25, isFullRefill: true)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.FuelConsumption.Should().ContainSingle();
        result.FuelConsumption[0].ValuePer100Km.Should().BeApproximately(11.25, 0.001);
        result.AverageFuelConsumptionPer100Km.Should().BeApproximately(11.25, 0.001);
    }

    [Fact]
    public void ComputeMetrics_FuelAndElectricConsumption_AreComputedIndependentlyForAHybrid()
    {
        var history = new[]
        {
            Refuel("f1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40, isFullRefill: true),
            Refuel("f2", new DateTime(2024, 2, 1), 1500, fuelVolume: 35, isFullRefill: true),
            Refuel("e1", new DateTime(2024, 1, 10), 1100, electricVolume: 15, isFullRefill: true),
            Refuel("e2", new DateTime(2024, 1, 20), 1300, electricVolume: 30, isFullRefill: true)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.FuelConsumption.Should().ContainSingle();
        result.FuelConsumption[0].ValuePer100Km.Should().BeApproximately(35.0 / 500 * 100, 0.001);

        result.ElectricConsumption.Should().ContainSingle();
        result.ElectricConsumption[0].ValuePer100Km.Should().BeApproximately(30.0 / 200 * 100, 0.001);
    }

    [Fact]
    public void ComputeMetrics_CostHistory_GroupsByMonthAndSplitsFuelFromMaintenance()
    {
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 5), 1000, fuelVolume: 40, cost: 60),
            Maintenance("h2", new DateTime(2024, 1, 20), 1050, cost: 150),
            Refuel("h3", new DateTime(2024, 2, 5), 1500, fuelVolume: 40, cost: 65)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.CostHistory.Should().HaveCount(2);
        var january = result.CostHistory[0];
        january.Period.Should().Be(new DateOnly(2024, 1, 1));
        january.FuelCost.Should().Be(60);
        january.MaintenanceCost.Should().Be(150);
        january.TotalCost.Should().Be(210);

        result.TotalCost.Should().Be(275);
    }

    [Fact]
    public void ComputeMetrics_NextMaintenance_IsNullWhenNoMaintenanceHistoryExists()
    {
        var history = new[] { Refuel("h1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40) };

        var result = CarMetricsService.ComputeMetrics(history);

        result.NextMaintenance.Should().BeNull();
    }

    [Fact]
    public void ComputeMetrics_NextMaintenance_IsOneYearAfterTheLastMaintenanceEvent()
    {
        var lastMaintenance = DateOnly.FromDateTime(DateTime.Today).AddMonths(-10);
        var history = new[] { Maintenance("h1", lastMaintenance.ToDateTime(TimeOnly.MinValue)) };

        var result = CarMetricsService.ComputeMetrics(history);

        result.NextMaintenance.Should().NotBeNull();
        result.NextMaintenance!.LastMaintenanceDate.Should().Be(lastMaintenance);
        result.NextMaintenance.DueDate.Should().Be(lastMaintenance.AddYears(1));
        result.NextMaintenance.MonthsRemaining.Should().Be(2);
    }

    [Fact]
    public void ComputeMetrics_NextMaintenance_ReportsNegativeMonthsWhenOverdue()
    {
        var lastMaintenance = DateOnly.FromDateTime(DateTime.Today).AddMonths(-14);
        var history = new[] { Maintenance("h1", lastMaintenance.ToDateTime(TimeOnly.MinValue)) };

        var result = CarMetricsService.ComputeMetrics(history);

        result.NextMaintenance!.MonthsRemaining.Should().Be(-2);
    }

    [Fact]
    public void ComputeMetrics_MileageWarnings_FlagsAnOdometerRegression()
    {
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 1), 5000, fuelVolume: 40),
            Refuel("h2", new DateTime(2024, 2, 1), 4800, fuelVolume: 40)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.MileageWarnings.Should().ContainSingle(w => w.CarHistoryId == "h2");
    }

    [Fact]
    public void ComputeMetrics_MileageWarnings_FlagsADeltaMismatchAndSuggestsAMissingEntry()
    {
        // the trip computer says 300 km since the last refuel, but the odometer jumped 900 km since the previous entry in the app -
        // a refuel was very likely never logged in between
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40),
            Refuel("h2", new DateTime(2024, 2, 1), 1900, fuelVolume: 40, deltaMileage: 300)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.MileageWarnings.Should().ContainSingle(w => w.CarHistoryId == "h2");
        result.MileageWarnings[0].Message.Should().Contain("missing");
    }

    [Fact]
    public void ComputeMetrics_MileageWarnings_FlagsADeltaMismatchWithoutSuggestingAMissingEntryWhenSmaller()
    {
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40),
            Refuel("h2", new DateTime(2024, 2, 1), 1300, fuelVolume: 40, deltaMileage: 500)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.MileageWarnings.Should().ContainSingle(w => w.CarHistoryId == "h2");
        result.MileageWarnings[0].Message.Should().NotContain("missing");
    }

    [Fact]
    public void ComputeMetrics_MileageWarnings_IsSilentWhenDeltaMileageMatchesWithinTolerance()
    {
        var history = new[]
        {
            Refuel("h1", new DateTime(2024, 1, 1), 1000, fuelVolume: 40),
            Refuel("h2", new DateTime(2024, 2, 1), 1500, fuelVolume: 40, deltaMileage: 500.4)
        };

        var result = CarMetricsService.ComputeMetrics(history);

        result.MileageWarnings.Should().BeEmpty();
    }
}
