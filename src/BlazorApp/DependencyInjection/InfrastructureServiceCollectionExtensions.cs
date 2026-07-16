namespace Keeptrack.BlazorApp.DependencyInjection;

internal static class InfrastructureServiceCollectionExtensions
{
    internal static void AddWebApiHttpClient(this IServiceCollection services, string webApiBaseUrl)
    {
        var webApiUri = new Uri(webApiBaseUrl);
        services.AddHttpClient<AlbumApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<BookApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<CarApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<CarHistoryApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<HouseApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<HouseHistoryApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<EpisodeApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<MovieApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<TvShowApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<VideoGameApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<SongApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<PlaylistApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.WatchNext.WatchNextApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.Wishlist.WishlistApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.Import.TvTimeImportApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.Import.CarHistoryImportApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.ReferenceData.ReferenceDataApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.ReferenceDataAdmin.ReferenceDataAdminApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        services.AddHttpClient<Components.Pages.StatsApiClient>(client => client.BaseAddress = webApiUri)
            .AddHttpMessageHandler<AuthenticationTokenHandler>();
        // deliberately NO AuthenticationTokenHandler: the shared-wishlist view is anonymous by design
        services.AddHttpClient<Components.Wishlist.SharedWishlistApiClient>(client => client.BaseAddress = webApiUri);
    }
}
