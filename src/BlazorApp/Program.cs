var builder = WebApplication.CreateBuilder(args);
builder.AddKeeptrackTelemetry();

// adds services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.AddKeeptrackAuthentication();
// Opt-in shared Data Protection key ring (see MongoDbXmlRepository), required for more than one replica,
// since the auth cookie and antiforgery tokens must decrypt on every replica.
// Left unset, the framework keeps its per-instance ephemeral keys.
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
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<Keeptrack.BlazorApp.Components.Account.AuthenticationTokenHandler>();
builder.Services.AddScoped<Keeptrack.BlazorApp.Components.Account.UserPreferencesState>();
builder.Services.AddScoped<Keeptrack.BlazorApp.Components.Inventory.ListViewPreference>();
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
// An anonymous share-link recipient must never open a SignalR circuit (see SharedWishlistPage.razor).
// This bypasses the globally interactive Routes and Router, since a per-component opt-out is impossible once an ancestor sets an interactive render mode.
app.MapGet("/shared/wishlist/{token}", (string token) =>
    new RazorComponentResult<Keeptrack.BlazorApp.Components.Wishlist.SharedWishlistApp>(new { Token = token }));
app.MapControllers();
app.MapHealthChecks("/healthz");

await app.RunAsync();

namespace Keeptrack.BlazorApp
{
    public partial class Program { }
}
