using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Shared fallback for a nullable DTO string member mapping to a Domain model member that has no
/// sensible default (typically <c>required</c>) - <c>BookDto.Title</c> is nullable while
/// <c>BookModel.Title</c> is <c>required</c> non-nullable, the <c>InventoryPageBase</c> <c>new()</c>-
/// constraint gotcha documented in CLAUDE.md. AutoMapper silently substituted <c>""</c> for a null
/// source string everywhere; this reproduces that one specific behavior deliberately, for exact parity,
/// rather than letting a missing title become a null reference deeper in the model. Attached to every
/// DTO mapper that has at least one such member via <c>[UseStaticMapper(typeof(CommonDtoMappings))]</c>.
/// Tightening this to a real 400 validation error for a missing title is a deliberate follow-up, not
/// part of this mechanical migration - see docs/automapper-removal-plan.md.
/// </summary>
public static class CommonDtoMappings
{
    [UserMapping]
    public static string ToRequiredString(string? value)
    {
        return value ?? string.Empty;
    }
}
