using System;

namespace Keeptrack.Common.System;

/// <summary>
/// Whether a refuel's total agrees with what was pumped.
/// A fill-up costs volume times unit price, so a total that disagrees means one of the three numbers was mistyped.
/// </summary>
/// <remarks>
/// It lives here rather than in <c>Domain</c> because the check runs while the user types in the car history form, and <c>BlazorApp</c> never references <c>Domain</c>.
/// A server-side check would reuse it rather than derive the arithmetic again with another tolerance.
/// The check only warns.
/// A receipt legitimately differs from the pump (a car wash on the same ticket, a loyalty discount), so a mismatch is shown, never blocked or overwritten.
/// </remarks>
public static class RefuelCostCheck
{
    /// <summary>
    /// The smallest discrepancy worth reporting, whatever the rounding allowance: one cent, since no total is more precise.
    /// </summary>
    private const double MinimumTolerance = 0.01;

    /// <summary>Half of the last digit a pump displays for a volume (0.01 L).</summary>
    private const double VolumeHalfUnit = 0.005;

    /// <summary>Half of the last digit a pump displays for a unit price (0.001 currency/unit).</summary>
    private const double UnitPriceHalfUnit = 0.0005;

    /// <summary>
    /// What this entry should have cost, or null when neither side has both of its numbers.
    /// A hybrid entry carrying both a fuel and an electric pair sums them.
    /// One rule thus covers combustion, electric and mixed refuels, with no branching on the car's energy type.
    /// </summary>
    public static double? ComputeExpectedCost(double? fuelVolume, double? fuelUnitPrice, double? electricVolume, double? electricUnitPrice)
    {
        double? expected = null;
        if (fuelVolume is { } volume && fuelUnitPrice is { } unitPrice) expected = volume * unitPrice;
        if (electricVolume is { } energy && electricUnitPrice is { } energyPrice) expected = (expected ?? 0) + energy * energyPrice;
        return expected;
    }

    /// <summary>
    /// How far the recorded total may sit from <see cref="ComputeExpectedCost"/> before it counts as a mistake.
    /// It derives from what the pump display rounds away rather than being a flat constant.
    /// The volume shows to 0.01 and the unit price to 0.001, so the product of the two displayed numbers can legitimately miss the real total by that much.
    /// The allowance grows with the fill, or every large tank would report a phantom discrepancy.
    /// </summary>
    public static double ComputeTolerance(double? fuelVolume, double? fuelUnitPrice, double? electricVolume, double? electricUnitPrice)
    {
        var tolerance = RoundingAllowance(fuelVolume, fuelUnitPrice) + RoundingAllowance(electricVolume, electricUnitPrice);
        return Math.Max(MinimumTolerance, tolerance);
    }

    /// <summary>
    /// True when <paramref name="cost"/> is consistent with the volumes and unit prices given.
    /// With no complete volume and price pair there is nothing to check, which is consistent.
    /// A missing total when one could be computed is not: that is the entry this check mainly exists to catch.
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
