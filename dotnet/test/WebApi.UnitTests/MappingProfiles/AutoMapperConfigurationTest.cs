using AutoMapper;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace KeepTrack.WebApi.UnitTests.MappingProfiles;

[Trait("Category", "UnitTests")]
public class AutoMapperConfigurationTest
{
    [Fact]
    public void WebApiAutoMapperProfile_ShouldBeValid()
    {
        var config = new MapperConfiguration(config =>
        {
            config.AddMaps(typeof(Program).Assembly);
        }, NullLoggerFactory.Instance);

        config.AssertConfigurationIsValid();
    }
}
