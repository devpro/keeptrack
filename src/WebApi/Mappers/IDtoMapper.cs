namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Maps between a public REST DTO and its Domain model.
/// Implemented per CRUD pair by a Mapperly <c>[Mapper]</c> partial class (<c>BookDtoMapper</c>) and injected into <see cref="Controllers.DataCrudControllerBase{TDto, TModel}"/>.
/// Read-only controllers (Watch Next, Wishlist, metrics, reference data) use a one-directional mapper class instead, having no DTO to model direction.
/// </summary>
public interface IDtoMapper<TDto, TModel>
{
    TModel ToModel(TDto dto);

    TDto ToDto(TModel model);
}
