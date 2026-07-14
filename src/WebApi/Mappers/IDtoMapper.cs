namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// Maps between a public REST DTO and its Domain model counterpart. Implemented per CRUD pair by a
/// Mapperly <c>[Mapper]</c> partial class (e.g. <c>BookDtoMapper</c>) and injected into
/// <see cref="Controllers.DataCrudControllerBase{TDto, TModel}"/> instead of AutoMapper's untyped
/// <c>IMapper</c>. Read-only feature controllers (WatchNext, Wishlist, Car/House metrics,
/// reference-data) use a small one-directional Model-to-DTO mapper class instead - they have no DTO ->
/// Model direction at all, so this bidirectional interface doesn't fit them.
/// </summary>
public interface IDtoMapper<TDto, TModel>
{
    TModel ToModel(TDto dto);

    TDto ToDto(TModel model);
}
