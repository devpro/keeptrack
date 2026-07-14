using Keeptrack.Domain.Models;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.WebApi.Mappers;

[Mapper(EnumMappingStrategy = EnumMappingStrategy.ByName)]
[UseStaticMapper(typeof(CommonDtoMappings))]
public partial class CarDtoMapper : IDtoMapper<CarDto, CarModel>
{
    // see BookDtoMapper.ToModel for why MapValue (not MapperIgnoreTarget) is required here
    [MapValue(nameof(CarModel.OwnerId), "")]
    public partial CarModel ToModel(CarDto dto);

    [MapperIgnoreSource(nameof(CarModel.OwnerId))]
    public partial CarDto ToDto(CarModel model);

    /// <summary>
    /// CarDto.EnergyType is nullable (CarEnergyType?) while CarModel.EnergyType is required - the same
    /// "nullable DTO member mapping to a required model member" gotcha as CommonDtoMappings.ToRequiredString,
    /// just for an enum instead of a string, so it can't reuse that helper. MapEnergyType below still gets
    /// the generated, drift-checked ByName enum conversion; only the null -> default fallback is hand-written.
    /// A Mapperly mapper class's partial methods must all be instance or all be static - both stay instance
    /// to match ToModel/ToDto above.
    /// </summary>
    [UserMapping]
    private Domain.Models.CarEnergyType ToRequiredCarEnergyType(Contracts.Dto.CarEnergyType? value)
    {
        return value.HasValue ? MapEnergyType(value.Value) : default;
    }

    private partial Domain.Models.CarEnergyType MapEnergyType(Contracts.Dto.CarEnergyType value);
}
