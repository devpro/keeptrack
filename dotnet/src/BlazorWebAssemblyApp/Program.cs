using KeepTrack.BlazorWebAssemblyApp;
using KeepTrack.BlazorWebAssemblyApp.Authorization;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");

builder.Services.AddOptions();
builder.Services.AddAuthorizationCore();
builder.Services.AddBlazoredLocalStorage();
builder.Services.AddScoped<ExternalAuthStateProvider>();
builder.Services.AddScoped<AuthenticationStateProvider>(provider => provider.GetRequiredService<ExternalAuthStateProvider>());
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.Configuration["Keeptrack:WebApi:Url"]) });

await builder.Build().RunAsync();
