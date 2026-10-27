using System.Text.Json;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// "Has this draft changed since it was opened" for a modal entry form, shared by the Car, House and Health history DTOs without a hand-written equality member each.
/// A JSON serialization diff suits these flat DTOs, and not anything with cycles or non-deterministic member order.
/// </summary>
public static class DirtyTracking
{
    public static bool IsDirty<T>(T pristine, T current) =>
        JsonSerializer.Serialize(pristine) != JsonSerializer.Serialize(current);
}
