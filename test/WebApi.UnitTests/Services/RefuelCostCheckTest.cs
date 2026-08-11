using AwesomeAssertions;
using Keeptrack.Common.System;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Services;

[Trait("Category", "UnitTests")]
public class RefuelCostCheckTest
{
    [Fact]
    public void ComputeExpectedCost_MultipliesFuelVolumeByUnitPrice()
    {
        RefuelCostCheck.ComputeExpectedCost(42.30, 1.789, null, null).Should().BeApproximately(75.67, 0.005);
    }

    [Fact]
    public void ComputeExpectedCost_SumsBothSidesForAHybridRefuel()
    {
        RefuelCostCheck.ComputeExpectedCost(20, 1.80, 10, 0.25).Should().BeApproximately(38.50, 0.005);
    }

    [Fact]
    public void ComputeExpectedCost_IsNullWhenNeitherSideHasBothNumbers()
    {
        // half a pair is not a computation - a volume with no unit price says nothing about the total
        RefuelCostCheck.ComputeExpectedCost(42.30, null, null, null).Should().BeNull();
        RefuelCostCheck.ComputeExpectedCost(null, 1.789, null, 0.25).Should().BeNull();
    }

    [Fact]
    public void ComputeExpectedCost_UsesTheElectricSideAloneForAnElectricRefuel()
    {
        RefuelCostCheck.ComputeExpectedCost(null, null, 32.5, 0.2190).Should().BeApproximately(7.12, 0.005);
    }

    [Fact]
    public void IsConsistent_AcceptsATotalMatchingTheProduct()
    {
        RefuelCostCheck.IsConsistent(75.67, 42.30, 1.789, null, null).Should().BeTrue();
    }

    [Fact]
    public void IsConsistent_AcceptsTheCentsThePumpsOwnDisplayRoundsAway()
    {
        // 42.30 x 1.789 is 75.6747; a receipt reading 75.68 (or 75.65, within what rounding the displayed
        // volume and unit price can hide) is the same fill-up, not a typo. Flagging these would make the
        // warning fire on nearly every correctly entered refuel, which is the fastest way to have it ignored.
        RefuelCostCheck.IsConsistent(75.68, 42.30, 1.789, null, null).Should().BeTrue();
        RefuelCostCheck.IsConsistent(75.65, 42.30, 1.789, null, null).Should().BeTrue();
    }

    [Fact]
    public void IsConsistent_ToleranceGrowsWithTheSizeOfTheFill()
    {
        // the allowance is derived from what the display rounds away, so it scales - a flat one would
        // either false-positive on a big tank or wave through a real error on a small one
        var small = RefuelCostCheck.ComputeTolerance(10, 1.80, null, null);
        var large = RefuelCostCheck.ComputeTolerance(80, 1.80, null, null);
        large.Should().BeGreaterThan(small);
    }

    [Fact]
    public void IsConsistent_RejectsAMistypedTotal()
    {
        // a transposed total (75.67 typed as 57.67) is exactly what this check exists to surface
        RefuelCostCheck.IsConsistent(57.67, 42.30, 1.789, null, null).Should().BeFalse();
    }

    [Fact]
    public void IsConsistent_RejectsAMistypedUnitPrice()
    {
        // the cost is right and the unit price is off by a factor of ten - the check doesn't care which of
        // the three numbers is wrong, only that they disagree
        RefuelCostCheck.IsConsistent(75.67, 42.30, 17.89, null, null).Should().BeFalse();
    }

    [Fact]
    public void IsConsistent_RejectsAMissingTotalWhenOneCouldBeComputed()
    {
        // "the cost should always be checked before creating" includes the case of it not being there at all
        RefuelCostCheck.IsConsistent(null, 42.30, 1.789, null, null).Should().BeFalse();
    }

    [Fact]
    public void IsConsistent_AcceptsAnythingWhenThereIsNothingToCheckAgainst()
    {
        // a maintenance invoice, or a refuel where only the total was recorded: no volume/price pair, so no
        // claim to contradict. The check must never block an entry it has no opinion about.
        RefuelCostCheck.IsConsistent(389.90, null, null, null, null).Should().BeTrue();
        RefuelCostCheck.IsConsistent(null, null, null, null, null).Should().BeTrue();
        RefuelCostCheck.IsConsistent(60.00, 33.10, null, null, null).Should().BeTrue();
    }

    [Fact]
    public void IsConsistent_ChecksBothSidesTogetherForAHybridRefuel()
    {
        RefuelCostCheck.IsConsistent(38.50, 20, 1.80, 10, 0.25).Should().BeTrue();
        // only the fuel half was paid for - the electric half is unaccounted for
        RefuelCostCheck.IsConsistent(36.00, 20, 1.80, 10, 0.25).Should().BeFalse();
    }
}
