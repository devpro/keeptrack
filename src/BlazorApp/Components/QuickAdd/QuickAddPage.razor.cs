using Keeptrack.BlazorApp.Components.Inventory.Shared;
using Keeptrack.BlazorApp.Components.Shared;
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

    [Inject] private CarApiClient CarApi { get; set; } = null!;

    [Inject] private CarHistoryApiClient CarHistoryApi { get; set; } = null!;

    [Inject] private HouseApiClient HouseApi { get; set; } = null!;

    [Inject] private HouseHistoryApiClient HouseHistoryApi { get; set; } = null!;

    [Inject] private HealthProfileApiClient HealthProfileApi { get; set; } = null!;

    [Inject] private HealthRecordApiClient HealthRecordApi { get; set; } = null!;

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

    private bool _parentsLoading;

    private List<CarDto>? _cars;

    private string? _selectedCarId;

    private CarHistoryDto _carEntry = CarHistoryForm.NewEntry("");

    private List<HouseDto>? _houses;

    private string? _selectedHouseId;

    private HouseHistoryDto _houseEntry = HouseHistoryForm.NewEntry("");

    private List<HealthProfileDto>? _healthProfiles;

    private string? _selectedProfileId;

    private HealthRecordDto _healthEntry = HealthRecordForm.NewEntry("");

    private CarDto? SelectedCar => _cars?.FirstOrDefault(c => c.Id == _selectedCarId);

    private bool ShowFuel => SelectedCar?.EnergyType != CarEnergyType.Electric;

    private bool ShowElectric => SelectedCar?.EnergyType is CarEnergyType.Electric or CarEnergyType.Hybrid;

    private static bool IsKnownType(string? type) => type is not null && KnownTypes.Contains(type);

    private static string FormTitle(string? type) => type switch
    {
        "movie" => "New movie",
        "tv-show" => "New TV show",
        "book" => "New book",
        "album" => "New album",
        "video-game" => "New video game",
        "car" => "New car record",
        "house" => "New house record",
        "health" => "New health record",
        _ => ""
    };

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
                _movie = new MovieDto();
                _movieOwned = false;
                _movieOwnedDraft = new OwnedVersionDto();
                break;
            case "tv-show":
                _tvShow = new TvShowDto();
                _tvShowOwned = false;
                _tvShowOwnedDraft = new OwnedVersionDto();
                break;
            case "book":
                _book = new BookDto();
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
            case "car":
                await EnsureCarsLoadedAsync();
                _carEntry = CarHistoryForm.NewEntry(_selectedCarId ?? "");
                break;
            case "house":
                await EnsureHousesLoadedAsync();
                _houseEntry = HouseHistoryForm.NewEntry(_selectedHouseId ?? "");
                break;
            case "health":
                await EnsureHealthProfilesLoadedAsync();
                _healthEntry = HealthRecordForm.NewEntry(_selectedProfileId ?? "");
                break;
        }
    }

    /// <summary>Fetches a record type's possible parents (delay-gated spinner, same as every detail page's
    /// own load) - shared by the three record types since the fetch-and-preselect algorithm is identical,
    /// only the DTO/client/target field differ.</summary>
    private async Task<List<TDto>> LoadParentsAsync<TDto>(InventoryApiClientBase<TDto> api) where TDto : IHasId
    {
        List<TDto>? items = null;
        await LoadingIndicator.RunAsync(FetchAsync(), v => _parentsLoading = v, StateHasChanged);
        return items!;

        async Task FetchAsync()
        {
            var result = await api.GetAsync("", 1, 100);
            items = result.Items;
        }
    }

    private async Task EnsureCarsLoadedAsync()
    {
        if (_cars is not null) return;
        _cars = await LoadParentsAsync(CarApi);
        // the common "I only have one car" case - preselect it silently instead of a one-option picker
        if (_cars.Count == 1) _selectedCarId = _cars[0].Id;
    }

    private async Task EnsureHousesLoadedAsync()
    {
        if (_houses is not null) return;
        _houses = await LoadParentsAsync(HouseApi);
        if (_houses.Count == 1) _selectedHouseId = _houses[0].Id;
    }

    private async Task EnsureHealthProfilesLoadedAsync()
    {
        if (_healthProfiles is not null) return;
        _healthProfiles = await LoadParentsAsync(HealthProfileApi);
        if (_healthProfiles.Count == 1) _selectedProfileId = _healthProfiles[0].Id;
    }

    private void SelectCar(string carId)
    {
        _selectedCarId = carId;
        _carEntry.CarId = carId;
    }

    private void SelectHouse(string houseId)
    {
        _selectedHouseId = houseId;
        _houseEntry.HouseId = houseId;
    }

    private void SelectHealthProfile(string profileId)
    {
        _selectedProfileId = profileId;
        _healthEntry.HealthProfileId = profileId;
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

    private Task SaveRecordAsync<TDto>(InventoryApiClientBase<TDto> api, TDto dto, string parentId, string parentRoute) where TDto : IHasId =>
        RunSaveAsync(async () =>
        {
            await api.AddAsync(dto);
            return $"{parentRoute}/{parentId}";
        });

    private Task SaveCarRecordAsync() =>
        _selectedCarId is null ? Task.CompletedTask : SaveRecordAsync(CarHistoryApi, _carEntry, _selectedCarId, "/cars");

    private Task SaveHouseRecordAsync() =>
        _selectedHouseId is null ? Task.CompletedTask : SaveRecordAsync(HouseHistoryApi, _houseEntry, _selectedHouseId, "/houses");

    private Task SaveHealthRecordAsync() =>
        _selectedProfileId is null ? Task.CompletedTask : SaveRecordAsync(HealthRecordApi, _healthEntry, _selectedProfileId, "/health");
}
