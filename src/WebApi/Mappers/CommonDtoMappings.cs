using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// The fallback for a nullable DTO string mapping to a <c>required</c> model member, such as <c>BookDto.Title</c> to <c>BookModel.Title</c> (the <c>InventoryPageBase</c> <c>new()</c> constraint, see docs/data-model.md).
/// A null becomes <c>""</c> rather than a null reference deeper in the model.
/// Attached through <c>[UseStaticMapper(typeof(CommonDtoMappings))]</c> to every DTO mapper with such a member.
/// </summary>
public static class CommonDtoMappings
{
    [UserMapping]
    public static string ToRequiredString(string? value)
    {
        return value ?? string.Empty;
    }
}
