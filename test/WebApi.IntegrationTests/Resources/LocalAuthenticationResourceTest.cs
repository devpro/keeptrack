using System;
using System.Net;
using System.Threading.Tasks;
using Keeptrack.Common.Hosting.Authentication;
using Keeptrack.Common.System;
using Keeptrack.Testing.Shared.Authentication;
using Keeptrack.WebApi.Contracts.Dto;
using Keeptrack.WebApi.IntegrationTests.Hosting;
using Xunit;

namespace Keeptrack.WebApi.IntegrationTests.Resources;

/// <summary>
/// The WebApi side of local authentication over HTTP, run in every mode through <see cref="LocalAuthenticationWebAppFactory"/>.
/// Local tokens also allow what one Firebase test account cannot: a member and a free account, to prove the policies reject them.
/// </summary>
public class LocalAuthenticationResourceTest(LocalAuthenticationWebAppFactory factory)
    : ResourceTestBase(factory), IClassFixture<LocalAuthenticationWebAppFactory>
{
    private const string CarEndpoint = "api/cars";

    public override ValueTask InitializeAsync()
    {
        Assert.SkipWhen(!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("KESTREL_WEBAPP_URL")),
            "An external host does not hold this run's generated signing key.");
        return base.InitializeAsync();
    }

    [Fact]
    public async Task ALocalToken_IsAccepted()
    {
        AuthenticateWith(TestAuthentication.IssueLocalToken(NewEmail(), "member"));

        await GetAsync<PagedResult<CarDto>>($"/{CarEndpoint}");
    }

    /// <summary>
    /// Ends signed in as the owner, since the registered cleanup deletes with the bearer current at that time.
    /// </summary>
    [Fact]
    public async Task AnItem_BelongsToTheEmail_AcrossTokens()
    {
        var ownerEmail = NewEmail();
        AuthenticateWith(TestAuthentication.IssueLocalToken(ownerEmail, "member"));
        var created = await CreateAsync($"/{CarEndpoint}", new CarDto { Name = $"Local auth {Guid.NewGuid():N}" });

        AuthenticateWith(TestAuthentication.IssueLocalToken(NewEmail(), "member"));
        await GetAsync($"/{CarEndpoint}/{created.Id}", HttpStatusCode.NotFound);

        AuthenticateWith(TestAuthentication.IssueLocalToken(ownerEmail.ToUpperInvariant(), "member"));
        await GetAsync<CarDto>($"/{CarEndpoint}/{created.Id}");
    }

    [Fact]
    public async Task ATokenSignedWithAnotherKey_Answers401()
    {
        var foreignIssuer = new LocalTokenIssuer(new LocalTokenSettings
        {
            SigningKey = LocalSigningKey.Generate(),
            Issuer = TestAuthentication.LocalIssuer,
            Audience = TestAuthentication.LocalAudience
        });
        AuthenticateWith(foreignIssuer.Issue(NewEmail(), "admin", DateTimeOffset.UtcNow, TimeSpan.FromHours(1)));

        await GetAsync($"/{CarEndpoint}", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AMember_IsForbiddenAnAdminEndpoint()
    {
        AuthenticateWith(TestAuthentication.IssueLocalToken(NewEmail(), "member"));

        await GetAsync("/api/reference-data/unresolved?type=TvShow", HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AFreeAccount_IsForbiddenAMemberEndpoint()
    {
        AuthenticateWith(TestAuthentication.IssueLocalToken(NewEmail(), null));

        await GetAsync($"/{CarEndpoint}", HttpStatusCode.Forbidden);
    }

    private static string NewEmail() => $"local-{Guid.NewGuid():N}@keeptrack.test";
}
