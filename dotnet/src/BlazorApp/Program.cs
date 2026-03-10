var builder = WebApplication.CreateBuilder(args);

// adds services to the container
builder.Services.AddControllers();
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
builder.Services.AddAuthorization();
builder.Services.AddSingleton(builder.Configuration.TryGetSection<FirebaseClientSettings>("Firebase:WebAppConfiguration"));
if (FirebaseApp.DefaultInstance is null)
{
    var firebaseJson = builder.Configuration.TryGetSection<string>("Firebase:ServiceAccount");
    var googleCredential = GoogleCredential.FromJson(firebaseJson);
    FirebaseApp.Create(new AppOptions { Credential = googleCredential });
}
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthenticationTokenHandler>();
builder.Services.AddWebApiHttpClient(builder.Configuration.TryGetSection<string>("WebApi:BaseUrl"));

var app = builder.Build();

// configures the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapControllers();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();
