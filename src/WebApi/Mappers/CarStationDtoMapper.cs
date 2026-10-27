using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

/// <summary>
/// <c>car_station</c> is shared, so unlike the other DTO mappers this one has no <c>OwnerId</c>.
/// </summary>
[Mapper]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class CarStationDtoMapper : IDtoMapper<CarStationDto, CarStationModel>
{
    // the repository derives the normalized key fields on every upsert, so a caller cannot decouple a station's key from its name
    [MapperIgnoreTarget(nameof(CarStationModel.BrandNameNormalized))]
    [MapperIgnoreTarget(nameof(CarStationModel.CityNormalized))]
    [MapperIgnoreSource(nameof(CarStationDto.UsageCount))]
    [MapperIgnoreSource(nameof(CarStationDto.DisplayName))]
    public partial CarStationModel ToModel(CarStationDto dto);

    // UsageCount is computed per request by the admin listing, and DisplayName is derived on the DTO
    [MapperIgnoreSource(nameof(CarStationModel.BrandNameNormalized))]
    [MapperIgnoreSource(nameof(CarStationModel.CityNormalized))]
    [MapperIgnoreTarget(nameof(CarStationDto.UsageCount))]
    [MapperIgnoreTarget(nameof(CarStationDto.DisplayName))]
    public partial CarStationDto ToDto(CarStationModel model);
}
