using System;

namespace Keeptrack.Common.System;

/// <summary>
/// The "does this refuel's total agree with what was actually pumped" rule: a fill-up's cost is
/// volume x unit price, and a total that disagrees means one of the three numbers was mistyped.
/// </summary>
/// <remarks>
/// Lives here, not in <c>Domain</c>, because the check has to run *while the user types* in the car
/// history form - and <c>BlazorApp</c> deliberately never references <c>Domain</c>. Declaring it once in
/// the one project both tiers see is what keeps a future server-side use (a <c>CarMetricsService</c>
/// warning alongside its mileage ones) from re-deriving the same arithmetic with a different tolerance.
/// The check only ever warns: a receipt legitimately differs from the pump (a car wash added to the same
/// ticket, a loyalty discount), so a mismatch is something to show, never something to block or overwrite.
/// </remarks>
public static class RefuelCostCheck
{
    /// <summary>
    /// Smallest discrepancy worth reporting, whatever the derived rounding allowance works out to - one
    /// cent, since no total can be more precise than that.
    /// </summary>
    private const double MinimumTolerance = 0.01;

    /// <summary>Half of the last digit a pump displays for a volume (0.01 L).</summary>
    private const double VolumeHalfUnit = 0.005;

    /// <summary>Half of the last digit a pump displays for a unit price (0.001 currency/unit).</summary>
    private const double UnitPriceHalfUnit = 0.0005;

    /// <summary>
    /// What this entry should have cost, or null when neither side has both of its numbers. A hybrid
    /// entry carrying both a fuel and an electric pair sums them, so the one rule covers a combustion,
    /// an electric and a mixed refuel without the caller branching on the car's energy type.
    /// </summary>
    public static double? ComputeExpectedCost(double? fuelVolume, double? fuelUnitPrice, double? electricVolume, double? electricUnitPrice)
    {
        double? expected = null;
        if (fuelVolume is { } volume && fuelUnitPrice is { } unitPrice) expected = volume * unitPrice;
        if (electricVolume is { } energy && electricUnitPrice is { } energyPrice) expected = (expected ?? 0) + energy * energyPrice;
        return expected;
    }

    /// <summary>
    /// How far the recorded total may sit from <see cref="ComputeExpectedCost"/> before it counts as a
    /// mistake. Derived from what the pump's own display rounds away rather than being a flat constant:
    /// the volume is shown to 0.01 and the unit price to 0.001, so the product of the two *displayed*
    /// numbers can legitimately miss the real total by that much - and the allowance has to grow with the
    /// size of the fill, or every large tank would report a phantom discrepancy.
    /// </summary>
    public static double ComputeTolerance(double? fuelVolume, double? fuelUnitPrice, double? electricVolume, double? electricUnitPrice)
    {
        var tolerance = RoundingAllowance(fuelVolume, fuelUnitPrice) + RoundingAllowance(electricVolume, electricUnitPrice);
        return Math.Max(MinimumTolerance, tolerance);
    }

    /// <summary>
    /// True when <paramref name="cost"/> is consistent with the volumes and unit prices given. Nothing to
    /// check against (no complete volume/price pair) is consistent by definition; a *missing* total when
    /// one could be computed is not - that's the entry this check mainly exists to catch.
    /// </summary>
    public static bool IsConsistent(double? cost, double? fuelVolume, double? fuelUnitPrice, double? electricVolume, double? electricUnitPrice)
    {
        var expected = ComputeExpectedCost(fuelVolume, fuelUnitPrice, electricVolume, electricUnitPrice);
        if (expected is null) return true;
        if (cost is null) return false;
        return Math.Abs(cost.Value - expected.Value) <= ComputeTolerance(fuelVolume, fuelUnitPrice, electricVolume, electricUnitPrice);
    }

    private static double RoundingAllowance(double? volume, double? unitPrice)
    {
        if (volume is not { } quantity || unitPrice is not { } price) return 0;
        return (VolumeHalfUnit * Math.Abs(price)) + (UnitPriceHalfUnit * Math.Abs(quantity));
    }
}
