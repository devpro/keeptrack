using Keeptrack.Common.System;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// House data transfer object.
/// </summary>
public class HouseDto : IHasId
{
    /// <summary>
    /// House ID.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// House name (e.g. "Main house", "Beach apartment").
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// Street address.
    /// </summary>
    public string? Address { get; set; }

    /// <summary>
    /// City.
    /// </summary>
    public string? City { get; set; }

    /// <summary>
    /// Postal code.
    /// </summary>
    public string? PostalCode { get; set; }

    /// <summary>
    /// Country.
    /// </summary>
    public string? Country { get; set; }

    /// <summary>
    /// Free-text notes.
    /// </summary>
    public string? Notes { get; set; }
}
