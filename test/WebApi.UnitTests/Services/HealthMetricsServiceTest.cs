using System;
using AwesomeAssertions;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Services;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class HealthMetricsServiceTest
{
    private readonly HealthMetricsService _service = new();

    private static HealthRecordModel Record(
        string id,
        DateTime date,
        HealthEventType eventType = HealthEventType.Appointment,
        string? practitioner = null,
        string? specialty = null,
        string? description = null,
        double? price = null,
        double? publicReimbursement = null,
        double? insuranceReimbursement = null,
        double? leftover = null) =>
        new()
        {
            Id = id,
            OwnerId = "owner",
            HealthProfileId = "profile-1",
            HistoryDate = date,
            EventType = eventType,
            Practitioner = practitioner,
            Specialty = specialty,
            Description = description,
            Price = price,
            PublicReimbursement = publicReimbursement,
            InsuranceReimbursement = insuranceReimbursement,
            NotCovered = leftover
        };

    [Fact]
    public void ComputeMetrics_IsAllEmpty_WhenThereAreNoRecords()
    {
        var result = _service.ComputeMetrics([]);

        result.CostHistory.Should().BeEmpty();
        result.LastVisits.Should().BeEmpty();
        result.UnbalancedRecords.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_CostHistory_GroupsByYear_AndComputesOutOfPocketAfterBothReimbursements()
    {
        var records = new[]
        {
            Record("r1", new DateTime(2025, 3, 10, 9, 0, 0), price: 30, publicReimbursement: 20, insuranceReimbursement: 8.5),
            Record("r2", new DateTime(2025, 9, 1, 14, 0, 0), price: 55),
            Record("r3", new DateTime(2026, 1, 15, 10, 0, 0), price: 26.5, publicReimbursement: 16.5)
        };

        var result = _service.ComputeMetrics(records);

        result.CostHistory.Should().HaveCount(2);
        var year2025 = result.CostHistory[0];
        year2025.Year.Should().Be(2025);
        year2025.TotalPaid.Should().Be(85);
        year2025.TotalReimbursed.Should().Be(28.5);
        year2025.OutOfPocket.Should().Be(56.5);

        var year2026 = result.CostHistory[1];
        year2026.Year.Should().Be(2026);
        year2026.TotalPaid.Should().Be(26.5);
        year2026.TotalReimbursed.Should().Be(16.5);
        year2026.OutOfPocket.Should().BeApproximately(10, 0.0001);
    }

    [Fact]
    public void ComputeMetrics_CostHistory_ExcludesRecordsWithNoMoneyAtAll()
    {
        // a sickness entry carries no money - it must not fabricate a zero-cost year
        var records = new[] { Record("r1", new DateTime(2025, 3, 10, 8, 0, 0), HealthEventType.Sickness, description: "Fever") };

        _service.ComputeMetrics(records).CostHistory.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_LastVisits_GroupsByPractitionerAndSpecialty_MostRecentFirst()
    {
        var records = new[]
        {
            Record("r1", new DateTime(2025, 1, 10, 9, 0, 0), practitioner: "Dr Martin", specialty: "dentiste"),
            Record("r2", new DateTime(2026, 2, 20, 11, 0, 0), practitioner: "Dr Martin", specialty: "dentiste"),
            Record("r3", new DateTime(2025, 6, 1, 15, 30, 0), practitioner: "Dr Diaz", specialty: "généraliste")
        };

        var result = _service.ComputeMetrics(records);

        result.LastVisits.Should().HaveCount(2);
        result.LastVisits[0].Practitioner.Should().Be("Dr Martin");
        result.LastVisits[0].LastVisitDate.Should().Be(new DateTime(2026, 2, 20, 11, 0, 0));
        result.LastVisits[0].VisitCount.Should().Be(2);
        result.LastVisits[1].Practitioner.Should().Be("Dr Diaz");
    }

    [Fact]
    public void ComputeMetrics_LastVisits_IgnoreSicknessEntriesAndAppointmentsWithoutAPractitioner()
    {
        var records = new[]
        {
            Record("r1", new DateTime(2025, 1, 10, 9, 0, 0), HealthEventType.Sickness, description: "Migraine"),
            Record("r2", new DateTime(2025, 2, 20, 11, 0, 0), specialty: "laboratoire")
        };

        _service.ComputeMetrics(records).LastVisits.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_UnbalancedRecords_FlagsEverythingThatDoesNotSumToZero_OldestFirst()
    {
        var records = new[]
        {
            // nothing entered yet: missing = the full price
            Record("r1", new DateTime(2026, 5, 2, 9, 0, 0), practitioner: "Dr Martin", price: 60),
            Record("r2", new DateTime(2026, 3, 1, 9, 0, 0), description: "Blood test", price: 25),
            // partially settled: ameli paid, the mutuelle (or the leftover) hasn't been entered - the
            // exact "did the mutuelle ever pay?" case the check exists for
            Record("r3", new DateTime(2026, 4, 1, 9, 0, 0), price: 30, publicReimbursement: 20),
            // free consultations never wait on anything
            Record("r4", new DateTime(2026, 6, 1, 9, 0, 0), practitioner: "Dr Diaz")
        };

        var result = _service.ComputeMetrics(records);

        result.UnbalancedRecords.Should().HaveCount(3);
        result.UnbalancedRecords[0].RecordId.Should().Be("r2");
        result.UnbalancedRecords[0].Label.Should().Be("Blood test");
        result.UnbalancedRecords[0].MissingAmount.Should().Be(25);
        result.UnbalancedRecords[1].RecordId.Should().Be("r3");
        result.UnbalancedRecords[1].MissingAmount.Should().Be(10);
        result.UnbalancedRecords[2].RecordId.Should().Be("r1");
        result.UnbalancedRecords[2].MissingAmount.Should().Be(60);
    }

    [Fact]
    public void ComputeMetrics_UnbalancedRecords_ConsidersARecordSettled_WhenPriceReimbursementsAndNotCoveredSumToZero()
    {
        // 26.50 = 16.50 (ameli) + 8 (mutuelle) + 2 (reste à charge): fully accounted for
        var records = new[]
        {
            Record("r1", new DateTime(2026, 2, 3, 9, 0, 0), price: 26.5, publicReimbursement: 16.5, insuranceReimbursement: 8, leftover: 2)
        };

        _service.ComputeMetrics(records).UnbalancedRecords.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_UnbalancedRecords_ToleratesSubCentFloatingPointResidue()
    {
        // 0.1 + 0.2 style double arithmetic must never flag a genuinely settled record
        var records = new[]
        {
            Record("r1", new DateTime(2026, 2, 3, 9, 0, 0), price: 0.3, publicReimbursement: 0.1, insuranceReimbursement: 0.2)
        };

        _service.ComputeMetrics(records).UnbalancedRecords.Should().BeEmpty();
    }

    [Fact]
    public void ComputeMetrics_UnbalancedRecords_FlagsOverPayments_WithANegativeMissingAmount()
    {
        var records = new[]
        {
            Record("r1", new DateTime(2026, 2, 3, 9, 0, 0), price: 30, publicReimbursement: 20, insuranceReimbursement: 15)
        };

        var result = _service.ComputeMetrics(records);

        var unbalanced = result.UnbalancedRecords.Should().ContainSingle().Subject;
        unbalanced.MissingAmount.Should().Be(-5);
    }
}
