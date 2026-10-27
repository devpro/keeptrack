using System;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

/// <summary>
/// The shared conversion between a model's <see cref="DateOnly"/> and an entity's <see cref="DateTime"/>, attached through <c>[UseStaticMapper(typeof(CommonStorageMappings))]</c>.
/// The driver's <c>DateTimeSerializer</c> requires <see cref="DateTimeKind.Utc"/>, so <see cref="ToDateTime"/> stamps it rather than leaving the kind unspecified.
/// </summary>
public static class CommonStorageMappings
{
    [UserMapping]
    public static DateOnly ToDateOnly(DateTime dateTime)
    {
        return DateOnly.FromDateTime(dateTime);
    }

    [UserMapping]
    public static DateTime ToDateTime(DateOnly dateOnly)
    {
        return dateOnly.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
    }
}
