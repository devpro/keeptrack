using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class BookDtoMapper : IDtoMapper<BookDto, BookModel>
{
    // OwnerId is required on the model, so ignoring it would not compile: MapValue fills it, and DataCrudControllerBase sets it from the caller's claims, never from client input
    [MapValue(nameof(BookModel.OwnerId), "")]
    // ImageUrl is hydrated by the server for display (see IReferenceLinkedDto), with no model counterpart
    [MapperIgnoreSource(nameof(BookDto.ImageUrl))]
    public partial BookModel ToModel(BookDto dto);

    [MapperIgnoreSource(nameof(BookModel.OwnerId))]
    [MapperIgnoreTarget(nameof(BookDto.ImageUrl))]
    public partial BookDto ToDto(BookModel model);
}
