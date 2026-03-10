namespace Keeptrack.BlazorApp.DependencyInjection;

internal static class InfrastructureServiceCollectionExtensions
{
    internal static void AddWebApiHttpClient(this IServiceCollection services, string webApiBaseUrl)
    {
        var webApiUri = new Uri(webApiBaseUrl);
        services.AddHttpClient<MoviesApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<BookApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
    }
}
