using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class BookDtoMapper : IDtoMapper<BookDto, BookModel>
{
    // OwnerId is `required` on BookModel, so it can't just be ignored (Mapperly's generated object
    // initializer would fail to compile) - MapValue satisfies the required-member constructor while
    // still leaving OwnerId to be set server-side from claims (DataCrudControllerBase), never from
    // client input, exactly like the ignored member it replaces.
    [MapValue(nameof(BookModel.OwnerId), "")]
    public partial BookModel ToModel(BookDto dto);

    [MapperIgnoreSource(nameof(BookModel.OwnerId))]
    public partial BookDto ToDto(BookModel model);
}
