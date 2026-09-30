using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// <c>car_station</c> is shared and owner-less, so unlike every other DTO mapper here this one has no
/// <c>OwnerId</c> to stamp or ignore.
/// </summary>
[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class CarStationDtoMapper : IDtoMapper<CarStationDto, CarStationModel>
{
    // The normalized natural-key fields are derived by the repository on every upsert, never sent by a
    // client - accepting them from input would let a caller decouple a station's key from its own name.
    [MapperIgnoreTarget(nameof(CarStationModel.BrandNameNormalized))]
    [MapperIgnoreTarget(nameof(CarStationModel.CityNormalized))]
    [MapperIgnoreSource(nameof(CarStationDto.UsageCount))]
    [MapperIgnoreSource(nameof(CarStationDto.DisplayName))]
    public partial CarStationModel ToModel(CarStationDto dto);

    // UsageCount is computed per request by the admin listing, not stored; DisplayName is derived on the DTO.
    [MapperIgnoreSource(nameof(CarStationModel.BrandNameNormalized))]
    [MapperIgnoreSource(nameof(CarStationModel.CityNormalized))]
    [MapperIgnoreTarget(nameof(CarStationDto.UsageCount))]
    [MapperIgnoreTarget(nameof(CarStationDto.DisplayName))]
    public partial CarStationDto ToDto(CarStationModel model);
}
