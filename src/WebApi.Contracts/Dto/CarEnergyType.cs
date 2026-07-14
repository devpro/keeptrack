namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// Car energy type.
/// </summary>
public enum CarEnergyType
{
    /// <summary>Combustion (petrol/diesel) engine.</summary>
    Combustion,

    /// <summary>Hybrid (combustion + electric).</summary>
    Hybrid,

    /// <summary>Fully electric.</summary>
    Electric
}
