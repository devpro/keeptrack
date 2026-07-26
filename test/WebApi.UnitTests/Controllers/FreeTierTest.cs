using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AwesomeAssertions;
using Keeptrack.Common.System;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Controllers;
using Keeptrack.WebApi.Import;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Controllers;

/// <summary>
/// Covers the free preview tier's two enforcement mechanisms: the creation quota in
/// <see cref="DataCrudControllerBase{TDto,TModel}.Post"/> (exercised directly with a non-member
/// principal - the integration suite's shared Firebase account is an admin, which the quota must
/// never count, so an HTTP-level test can't reach this path), and the "MemberOnly" policy attribute
/// on every restricted controller (a reflection guard, so removing one is a failing test rather
/// than a silent public giveaway).
/// </summary>
[Trait("Category", "UnitTests")]
public class FreeTierTest
{
    private const int ConfiguredLimit = 2;

    public class TestDto : IHasId
    {
        public string? Id { get; set; }
    }

    public class TestModel : IHasIdAndOwnerId
    {
        public string? Id { get; set; }

        public required string OwnerId { get; set; }
    }

    private sealed class TestMapper : IDtoMapper<TestDto, TestModel>
    {
        public TestModel ToModel(TestDto dto) => new() { Id = dto.Id, OwnerId = "" };

        public TestDto ToDto(TestModel model) => new() { Id = model.Id };
    }

    private sealed class FakeRepository(long existingCount) : IDataRepository<TestModel>
    {
        public Task<long> CountAsync(string ownerId) => Task.FromResult(existingCount);

        public Task<TestModel> CreateAsync(TestModel model)
        {
            model.Id = Guid.NewGuid().ToString();
            return Task.FromResult(model);
        }

        public Task<TestModel?> FindOneAsync(string id, string ownerId) => Task.FromResult<TestModel?>(null);

        public Task<PagedResult<TestModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TestModel input, string? sort = null) =>
            Task.FromResult(new PagedResult<TestModel>([], 0, page, pageSize));

        public Task<long> UpdateAsync(string id, TestModel model, string ownerId) => Task.FromResult(1L);

        public Task<long> DeleteAsync(string id, string ownerId) => Task.FromResult(1L);
    }

    private sealed class CappedTestController(IDataRepository<TestModel> repository)
        : DataCrudControllerBase<TestDto, TestModel>(new TestMapper(), repository)
    {
        protected override int FreeTierLimitFactor => 1;
    }

    private static CappedTestController CreateController(long existingCount, params string[] roles)
    {
        var claims = new List<Claim> { new("user_id", "user-1") };
        claims.AddRange(roles.Select(role => new Claim("role", role)));

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Features:FreeTierItemLimit"] = ConfiguredLimit.ToString() })
            .Build();
        var services = new ServiceCollection()
            .AddSingleton<IConfiguration>(configuration)
            .BuildServiceProvider();

        return new CappedTestController(new FakeRepository(existingCount))
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test")),
                    RequestServices = services
                }
            }
        };
    }

    [Fact]
    public async Task Post_CreatesTheItem_WhileANonMemberIsUnderTheLimit()
    {
        var controller = CreateController(existingCount: ConfiguredLimit - 1);

        var result = await controller.Post(new TestDto());

        result.Should().BeOfType<CreatedAtActionResult>();
    }

    [Fact]
    public async Task Post_Returns403WithAnErrorBody_WhenANonMemberIsAtTheLimit()
    {
        var controller = CreateController(existingCount: ConfiguredLimit);

        var result = await controller.Post(new TestDto());

        var objectResult = result.Should().BeOfType<ObjectResult>().Subject;
        objectResult.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        objectResult.Value!.ToString().Should().Contain("membership");
    }

    [Fact]
    public async Task Post_NeverCapsAMember()
    {
        var controller = CreateController(existingCount: ConfiguredLimit + 100, "member");

        (await controller.Post(new TestDto())).Should().BeOfType<CreatedAtActionResult>();
    }

    [Fact]
    public async Task Post_NeverCapsAnAdmin()
    {
        var controller = CreateController(existingCount: ConfiguredLimit + 100, "admin");

        (await controller.Post(new TestDto())).Should().BeOfType<CreatedAtActionResult>();
    }

    /// <summary>
    /// The restricted controllers must all require the membership policy - and the free-tier ones must
    /// not, or free accounts would be locked out of the preview itself.
    /// </summary>
    [Theory]
    [InlineData(typeof(BookController), "MemberOnly")]
    [InlineData(typeof(AlbumController), "MemberOnly")]
    [InlineData(typeof(PlaylistController), "MemberOnly")]
    [InlineData(typeof(SongController), "MemberOnly")]
    [InlineData(typeof(VideoGameController), "MemberOnly")]
    [InlineData(typeof(CarController), "MemberOnly")]
    [InlineData(typeof(CarHistoryController), "MemberOnly")]
    [InlineData(typeof(HouseController), "MemberOnly")]
    [InlineData(typeof(HouseHistoryController), "MemberOnly")]
    [InlineData(typeof(HealthProfileController), "MemberOnly")]
    [InlineData(typeof(HealthRecordController), "MemberOnly")]
    [InlineData(typeof(CollectibleController), "MemberOnly")]
    [InlineData(typeof(GearController), "MemberOnly")]
    [InlineData(typeof(TvTimeImportController), "MemberOnly")]
    [InlineData(typeof(CarHistoryImportController), "MemberOnly")]
    [InlineData(typeof(HealthImportController), "MemberOnly")]
    [InlineData(typeof(MovieController), null)]
    [InlineData(typeof(TvShowController), null)]
    [InlineData(typeof(EpisodeController), null)]
    public void Controller_CarriesTheExpectedAuthorizationPolicy(Type controllerType, string? expectedPolicy)
    {
        var attribute = controllerType.GetCustomAttributes(typeof(AuthorizeAttribute), inherit: false)
            .Cast<AuthorizeAttribute>()
            .Single();

        attribute.Policy.Should().Be(expectedPolicy);
    }
}
