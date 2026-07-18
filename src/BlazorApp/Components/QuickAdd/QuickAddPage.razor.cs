using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;
using Microsoft.AspNetCore.Components;

namespace Keeptrack.BlazorApp.Components.QuickAdd;

public partial class QuickAddPage : ComponentBase
{
    private static readonly string[] KnownTypes =
        ["movie", "tv-show", "book", "album", "video-game", "car", "house", "health"];

    [Inject] private NavigationManager Navigation { get; set; } = null!;

    [Inject] private MovieApiClient MovieApi { get; set; } = null!;

    [Inject] private TvShowApiClient TvShowApi { get; set; } = null!;

    [Inject] private BookApiClient BookApi { get; set; } = null!;

    [Inject] private AlbumApiClient AlbumApi { get; set; } = null!;

    [Inject] private VideoGameApiClient VideoGameApi { get; set; } = null!;

    /// <summary>
    /// The selected type lives in the URL (list-page URL-state convention) so the browser back button
    /// returns from a form to the picker, and a specific type is deep-linkable/bookmarkable.
    /// </summary>
    [SupplyParameterFromQuery(Name = "type")]
    public string? Type { get; set; }

    private string? _loadedType;

    private string? _error;

    private bool _saving;

    private MovieDto _movie = new();

    private bool _movieOwned;

    private OwnedVersionDto _movieOwnedDraft = new();

    private TvShowDto _tvShow = new();

    private bool _tvShowOwned;

    private OwnedVersionDto _tvShowOwnedDraft = new();

    private BookDto _book = new();

    private bool _bookOwned;

    private OwnedVersionDto _bookOwnedDraft = new();

    private AlbumDto _album = new();

    private bool _albumOwned;

    private OwnedVersionDto _albumOwnedDraft = new();

    private VideoGameDto _videoGame = new();

    private VideoGamePlatformDto _videoGamePlatformDraft = new();

    private static bool IsKnownType(string? type) => type is not null && KnownTypes.Contains(type);

    /// <summary>
    /// Only rebuilds the draft on an actual type change - this also fires on unrelated parameter updates
    /// (e.g. a cascading auth-state refresh), which must not wipe a half-filled form.
    /// </summary>
    protected override async Task OnParametersSetAsync()
    {
        if (Type == _loadedType) return;
        _loadedType = Type;
        _error = null;
        _saving = false;

        switch (Type)
        {
            case "movie":
                // defaults to today for the "just saw it" scenario - visible and clearable, since
                // prefilling it marks the movie Seen
                _movie = new MovieDto { FirstSeenAt = DateOnly.FromDateTime(DateTime.Today) };
                _movieOwned = false;
                _movieOwnedDraft = new OwnedVersionDto();
                break;
            case "tv-show":
                _tvShow = new TvShowDto();
                _tvShowOwned = false;
                _tvShowOwnedDraft = new OwnedVersionDto();
                break;
            case "book":
                _book = new BookDto { FirstReadAt = DateOnly.FromDateTime(DateTime.Today) };
                _bookOwned = false;
                _bookOwnedDraft = new OwnedVersionDto();
                break;
            case "album":
                _album = new AlbumDto();
                _albumOwned = false;
                _albumOwnedDraft = new OwnedVersionDto();
                break;
            case "video-game":
                _videoGame = new VideoGameDto();
                _videoGamePlatformDraft = new VideoGamePlatformDto();
                break;
        }

        await Task.CompletedTask;
    }

    /// <summary>Shared error/saving-state handling for every Save button; each caller only supplies the
    /// save action and the route to land on afterward.</summary>
    private async Task RunSaveAsync(Func<Task<string>> save)
    {
        _error = null;
        _saving = true;
        try
        {
            Navigation.NavigateTo(await save());
        }
        catch (Exception ex)
        {
            _error = ex.Message;
        }
        finally
        {
            _saving = false;
        }
    }

    private Task SaveMediaAsync<TDto>(InventoryApiClientBase<TDto> api, TDto dto, string route) where TDto : IHasId =>
        RunSaveAsync(async () =>
        {
            var created = await api.AddAsync(dto);
            return $"{route}/{created.Id}";
        });

    private Task SaveMovieAsync()
    {
        if (_movieOwned) _movie.OwnedVersions = [_movieOwnedDraft];
        return SaveMediaAsync(MovieApi, _movie, "/movies");
    }

    private Task SaveTvShowAsync()
    {
        if (_tvShowOwned) _tvShow.OwnedVersions = [_tvShowOwnedDraft];
        return SaveMediaAsync(TvShowApi, _tvShow, "/tv-shows");
    }

    private Task SaveBookAsync()
    {
        if (_bookOwned) _book.OwnedVersions = [_bookOwnedDraft];
        return SaveMediaAsync(BookApi, _book, "/books");
    }

    private Task SaveAlbumAsync()
    {
        if (_albumOwned) _album.OwnedVersions = [_albumOwnedDraft];
        return SaveMediaAsync(AlbumApi, _album, "/albums");
    }

    private Task SaveVideoGameAsync()
    {
        // choosing a platform is what makes the game owned - no platform selected means an unowned game
        if (!string.IsNullOrEmpty(_videoGamePlatformDraft.Platform))
        {
            _videoGame.Platforms = [_videoGamePlatformDraft];
        }

        return SaveMediaAsync(VideoGameApi, _videoGame, "/video-games");
    }
}
