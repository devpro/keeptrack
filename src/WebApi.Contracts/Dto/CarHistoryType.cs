namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Car history event type.
/// </summary>
public enum CarHistoryType
{
    /// <summary>Fuel refill or electric recharge.</summary>
    Refuel,

    /// <summary>Maintenance/service.</summary>
    Maintenance,

    /// <summary>Anything else (insurance, inspection, tires, ...).</summary>
    Other
}
