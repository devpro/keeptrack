var builder = WebApplication.CreateBuilder(args);

// adds services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/auth/logout";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireClaim("role", "admin"));
    // mirrors WebApi's policy (the cookie principal carries the same Firebase "role" claim): members and
    // admins see the whole app; everyone else is the free preview tier (movies + TV shows). This only
    // drives what the UI shows - the API enforces the same rule on every request.
    options.AddPolicy("MemberOnly", policy => policy.RequireClaim("role", "member", "admin"));
});
// opt-in shared Data Protection key ring (see MongoDbXmlRepository) - required before running more than
// one replica of this app, since the auth cookie and antiforgery tokens must decrypt on every replica.
// Left unset (the default), the framework keeps its usual per-instance ephemeral keys.
var dataProtectionConnectionString = builder.Configuration["DataProtection:MongoDb:ConnectionString"];
if (!string.IsNullOrEmpty(dataProtectionConnectionString))
{
    var keyCollection = new MongoClient(dataProtectionConnectionString)
        .GetDatabase(builder.Configuration["DataProtection:MongoDb:DatabaseName"] ?? "keeptrack")
        .GetCollection<MongoDbXmlRepository.DataProtectionKey>(MongoDbXmlRepository.CollectionName);
    builder.Services.AddDataProtection()
        .SetApplicationName("keeptrack")
        .AddKeyManagementOptions(options => options.XmlRepository = new MongoDbXmlRepository(keyCollection));
}
builder.Services.AddControllers();
builder.Services.AddSingleton(builder.Configuration.TryGetSection<FirebaseClientSettings>("Firebase:WebAppConfiguration"));
if (FirebaseApp.DefaultInstance is null)
{
    var firebaseJson = builder.Configuration.TryGetSection<string>("Firebase:ServiceAccount");
    var googleCredential = CredentialFactory.FromJson<ServiceAccountCredential>(firebaseJson).ToGoogleCredential();
    FirebaseApp.Create(new AppOptions { Credential = googleCredential });
}
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthenticationTokenHandler>();
builder.Services.AddWebApiHttpClient(builder.Configuration.TryGetSection<string>("WebApi:BaseUrl"));
builder.Services.AddHealthChecks();

var app = builder.Build();

// configures the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
if (builder.Configuration.GetValue<bool>("Features:IsHttpsRedirectionEnabled"))
{
    app.UseHttpsRedirection();
}
app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
// Anonymous share-link recipients must never open a SignalR circuit (see SharedWishlistPage.razor) -
// this bypasses the now-globally-interactive Routes/Router entirely rather than relying on a
// per-component opt-out, which isn't possible once an ancestor establishes an interactive render mode.
app.MapGet("/shared/wishlist/{token}", (string token) =>
    new RazorComponentResult<SharedWishlistApp>(new { Token = token }));
app.MapControllers();
app.MapHealthChecks("/health");

await app.RunAsync();

namespace Keeptrack.BlazorApp
{
    public partial class Program { }
}
