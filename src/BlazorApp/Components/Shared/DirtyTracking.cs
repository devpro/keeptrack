using System.Text.Json;

namespace Keeptrack.BlazorApp.Components.Shared;

/// <summary>
/// Generic "has this draft changed since it was opened" check for a modal entry form, shared across DTO
/// types (Car/House/Health history entries) without giving each one its own hand-written equality member.
/// A JSON-serialization diff is good enough for these flat DTOs - it's not meant for anything with cycles
/// or non-deterministic member order.
/// </summary>
public static class DirtyTracking
{
    public static bool IsDirty<T>(T pristine, T current) =>
        JsonSerializer.Serialize(pristine) != JsonSerializer.Serialize(current);
}
