using Keeptrack.BlazorApp.Components.Account;
using Keeptrack.Common.Hosting.Authentication;

namespace Keeptrack.BlazorApp.DependencyInjection;

internal static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// The cookie and policies every mode shares, then the active mode's own services (see docs/authentication.md).
    /// Read from the builder's configuration, since the mode decides what is registered.
    /// </summary>
    internal static void AddKeeptrackAuthentication(this WebApplicationBuilder builder)
    {
        var mode = AuthenticationSettings.ResolveMode(builder.Configuration, builder.Environment.EnvironmentName);
        builder.Services.AddSingleton(new AuthenticationSettings(mode));

        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/auth/logout";
                options.ExpireTimeSpan = AuthenticationSettings.SessionLifetime;
                options.SlidingExpiration = true;
            });
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin"))
            // Mirrors WebApi's policy, the cookie principal carrying the same "role" claim:
            // members and admins see the whole app, everyone else the free preview tier (movies and TV shows).
            // This only drives what the UI shows, and the API enforces the same rule on every request.
            .AddPolicy("MemberOnly", policy => policy.RequireClaim("role", "member", "admin"));
        builder.Services.AddControllers()
            .ConfigureApplicationPartManager(manager => manager.FeatureProviders.Add(new AuthenticationModeControllerFilter(mode)));

        switch (mode)
        {
            case AuthenticationMode.Firebase:
                builder.Services.AddSingleton(builder.Configuration.TryGetSection<FirebaseClientSettings>("Firebase:WebAppConfiguration"));
                if (FirebaseApp.DefaultInstance is null)
                {
                    var firebaseJson = builder.Configuration.TryGetSection<string>("Firebase:ServiceAccount");
                    var googleCredential = CredentialFactory.FromJson<ServiceAccountCredential>(firebaseJson).ToGoogleCredential();
                    FirebaseApp.Create(new AppOptions { Credential = googleCredential });
                }
                break;
            case AuthenticationMode.Local:
                // built here rather than by the container, so a bad key stops the host instead of failing the first sign-in
                builder.Services.AddSingleton(new LocalTokenIssuer(builder.Configuration.TryGetSection<LocalTokenSettings>("Authentication:Local")));
                break;
        }
    }
}
