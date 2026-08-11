using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
using Keeptrack.WebApi.Mappers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using DomainShareCategory = Keeptrack.Domain.Models.ShareCategory;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// The recipient side of sharing: browse the collections other users have shared with the caller, read-only
/// - with the same search/filter/sort the caller's own lists have - and copy a media item into the caller's
/// own collection. Every read/copy re-verifies, server-side, that the grant is addressed to the caller's own
/// email and that the requested category is in scope; the share id alone never grants access. MemberOnly:
/// sharing is not part of the free preview tier.
/// </summary>
[ApiController]
[Authorize(Policy = "MemberOnly")]
[Route("api/shared-with-me")]
public class SharedWithMeController(
    IShareRepository shareRepository,
    ShareDtoMapper shareMapper,
    IMovieRepository movieRepository,
    ITvShowRepository tvShowRepository,
    IBookRepository bookRepository,
    IAlbumRepository albumRepository,
    IVideoGameRepository videoGameRepository,
    ICollectibleRepository collectibleRepository,
    IGearRepository gearRepository,
    IMovieReferenceRepository movieReferenceRepository,
    ITvShowReferenceRepository tvShowReferenceRepository,
    IBookReferenceRepository bookReferenceRepository,
    IAlbumReferenceRepository albumReferenceRepository,
    IVideoGameReferenceRepository videoGameReferenceRepository,
    IDtoMapper<MovieDto, MovieModel> movieMapper,
    IDtoMapper<TvShowDto, TvShowModel> tvShowMapper,
    IDtoMapper<BookDto, BookModel> bookMapper,
    IDtoMapper<AlbumDto, AlbumModel> albumMapper,
    IDtoMapper<VideoGameDto, VideoGameModel> videoGameMapper,
    IDtoMapper<CollectibleDto, CollectibleModel> collectibleMapper,
    IDtoMapper<GearDto, GearModel> gearMapper,
    ICarRepository carRepository,
    ICarHistoryRepository carHistoryRepository,
    ICarStationRepository carStationRepository,
    IHouseRepository houseRepository,
    IHouseHistoryRepository houseHistoryRepository,
    IHealthProfileRepository healthProfileRepository,
    IHealthRecordRepository healthRecordRepository,
    IDtoMapper<CarDto, CarModel> carMapper,
    IDtoMapper<CarHistoryDto, CarHistoryModel> carHistoryMapper,
    IDtoMapper<HouseDto, HouseModel> houseMapper,
    IDtoMapper<HouseHistoryDto, HouseHistoryModel> houseHistoryMapper,
    IDtoMapper<HealthProfileDto, HealthProfileModel> healthProfileMapper,
    IDtoMapper<HealthRecordDto, HealthRecordModel> healthRecordMapper,
    CarMetricsDtoMapper carMetricsMapper,
    HouseMetricsDtoMapper houseMetricsMapper,
    HealthMetricsDtoMapper healthMetricsMapper) : ControllerBase
{
    /// <summary>Every collection shared with the caller (matched by their account email), oldest first.</summary>
    [HttpGet]
    [ProducesResponseType(200)]
    public async Task<ActionResult<List<SharedCollectionSummaryDto>>> Get()
    {
        var email = this.GetEmail();
        if (email is null)
        {
            // a caller with no email claim can't be anyone's recipient - an empty list, not an error
            return Ok(new List<SharedCollectionSummaryDto>());
        }

        var grants = await shareRepository.FindAllByRecipientEmailAsync(email);
        return Ok(grants.ConvertAll(shareMapper.ToSummaryDto));
    }

    // ---- reads (one per media category; personal categories are a later phase) ----

    [HttpGet("{shareId}/movies")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<MovieDto>>> GetMovies(string shareId, [FromQuery] PagedRequest paging, [FromQuery] MovieDto filter) =>
        ReadAsync(shareId, DomainShareCategory.Movies, movieRepository, movieMapper, filter, paging, MovieKey,
            items => ReferenceImageHydrator.HydrateAsync(items, movieReferenceRepository.FindByIdsAsync, x => x.ImageUrl));

    [HttpGet("{shareId}/tv-shows")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<TvShowDto>>> GetTvShows(string shareId, [FromQuery] PagedRequest paging, [FromQuery] TvShowDto filter) =>
        ReadAsync(shareId, DomainShareCategory.TvShows, tvShowRepository, tvShowMapper, filter, paging, TvShowKey,
            items => ReferenceImageHydrator.HydrateAsync(items, tvShowReferenceRepository.FindByIdsAsync, x => x.ImageUrl));

    [HttpGet("{shareId}/books")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<BookDto>>> GetBooks(string shareId, [FromQuery] PagedRequest paging, [FromQuery] BookDto filter) =>
        ReadAsync(shareId, DomainShareCategory.Books, bookRepository, bookMapper, filter, paging, BookKey,
            items => ReferenceImageHydrator.HydrateWithCustomOverrideAsync(items, bookReferenceRepository.FindByIdsAsync, x => x.ImageUrl, x => x.CustomImageUrl));

    [HttpGet("{shareId}/albums")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<AlbumDto>>> GetAlbums(string shareId, [FromQuery] PagedRequest paging, [FromQuery] AlbumDto filter) =>
        ReadAsync(shareId, DomainShareCategory.Albums, albumRepository, albumMapper, filter, paging, AlbumKey,
            items => ReferenceImageHydrator.HydrateWithCustomOverrideAsync(items, albumReferenceRepository.FindByIdsAsync, x => x.ImageUrl, x => x.CustomImageUrl));

    [HttpGet("{shareId}/video-games")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<VideoGameDto>>> GetVideoGames(string shareId, [FromQuery] PagedRequest paging, [FromQuery] VideoGameDto filter) =>
        ReadAsync(shareId, DomainShareCategory.VideoGames, videoGameRepository, videoGameMapper, filter, paging, VideoGameKey,
            items => ReferenceImageHydrator.HydrateWithCustomOverrideAsync(items, videoGameReferenceRepository.FindByIdsAsync, x => x.ImageUrl, x => x.CustomImageUrl));

    // ---- collection reads (collectibles/gear: same read-only list as media, but view-only - no shared
    //      reference to hydrate a cover from and no copy, so a leaner paged read than the media path) ----

    [HttpGet("{shareId}/collectibles")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<CollectibleDto>>> GetCollectibles(string shareId, [FromQuery] PagedRequest paging, [FromQuery] CollectibleDto filter) =>
        ReadOwnedListAsync(shareId, DomainShareCategory.Collectibles, collectibleRepository, collectibleMapper, filter, paging);

    [HttpGet("{shareId}/gear")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<SharedCategoryPageDto<GearDto>>> GetGear(string shareId, [FromQuery] PagedRequest paging, [FromQuery] GearDto filter) =>
        ReadOwnedListAsync(shareId, DomainShareCategory.Gears, gearRepository, gearMapper, filter, paging);

    // ---- copy into the caller's own collection (media only, idempotent) ----

    [HttpPost("{shareId}/movies/{itemId}/copy")]
    [ProducesResponseType(200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public Task<ActionResult<CopyResultDto<MovieDto>>> CopyMovie(string shareId, string itemId) =>
        CopyAsync(shareId, DomainShareCategory.Movies, itemId, movieRepository, movieMapper, SharedItemCopyService.CopyMovie, MovieKey);

    [HttpPost("{shareId}/tv-shows/{itemId}/copy")]
    [ProducesResponseType(200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public Task<ActionResult<CopyResultDto<TvShowDto>>> CopyTvShow(string shareId, string itemId) =>
        CopyAsync(shareId, DomainShareCategory.TvShows, itemId, tvShowRepository, tvShowMapper, SharedItemCopyService.CopyTvShow, TvShowKey);

    [HttpPost("{shareId}/books/{itemId}/copy")]
    [ProducesResponseType(200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public Task<ActionResult<CopyResultDto<BookDto>>> CopyBook(string shareId, string itemId) =>
        CopyAsync(shareId, DomainShareCategory.Books, itemId, bookRepository, bookMapper, SharedItemCopyService.CopyBook, BookKey);

    [HttpPost("{shareId}/albums/{itemId}/copy")]
    [ProducesResponseType(200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public Task<ActionResult<CopyResultDto<AlbumDto>>> CopyAlbum(string shareId, string itemId) =>
        CopyAsync(shareId, DomainShareCategory.Albums, itemId, albumRepository, albumMapper, SharedItemCopyService.CopyAlbum, AlbumKey);

    [HttpPost("{shareId}/video-games/{itemId}/copy")]
    [ProducesResponseType(200)]
    [ProducesResponseType(403)]
    [ProducesResponseType(404)]
    public Task<ActionResult<CopyResultDto<VideoGameDto>>> CopyVideoGame(string shareId, string itemId) =>
        CopyAsync(shareId, DomainShareCategory.VideoGames, itemId, videoGameRepository, videoGameMapper, SharedItemCopyService.CopyVideoGame, VideoGameKey);

    // ---- personal reads (cars/houses/health: list + full read-only detail, never copyable) ----

    [HttpGet("{shareId}/cars")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<List<CarDto>>> GetCars(string shareId) =>
        ReadPersonalListAsync(shareId, DomainShareCategory.Cars, carRepository, carMapper);

    [HttpGet("{shareId}/cars/{carId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<SharedDetailDto<CarDto, CarHistoryDto, CarMetricsDto>>> GetCar(string shareId, string carId)
    {
        var loaded = await LoadSharedParentAsync(shareId, DomainShareCategory.Cars, carId, carRepository, carHistoryRepository,
            (id, owner) => new CarHistoryModel { OwnerId = owner, CarId = id, EventType = default, HistoryDate = default });
        if (loaded is null)
        {
            return NotFound();
        }

        var (car, history, ownerName) = loaded.Value;
        var entries = history.ConvertAll(carHistoryMapper.ToDto);
        // a recipient sees the same station names as the owner - the catalogue is shared and owner-less,
        // so this is the one hydration that needs no ownership check of its own
        await CarStationHydrator.HydrateAsync(entries, carStationRepository);
        return Ok(new SharedDetailDto<CarDto, CarHistoryDto, CarMetricsDto>
        {
            Parent = carMapper.ToDto(car),
            Children = entries,
            Metrics = carMetricsMapper.ToDto(CarMetricsService.ComputeMetrics(history)),
            OwnerDisplayName = ownerName
        });
    }

    [HttpGet("{shareId}/houses")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<List<HouseDto>>> GetHouses(string shareId) =>
        ReadPersonalListAsync(shareId, DomainShareCategory.Houses, houseRepository, houseMapper);

    [HttpGet("{shareId}/houses/{houseId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<SharedDetailDto<HouseDto, HouseHistoryDto, HouseMetricsDto>>> GetHouse(string shareId, string houseId)
    {
        var loaded = await LoadSharedParentAsync(shareId, DomainShareCategory.Houses, houseId, houseRepository, houseHistoryRepository,
            (id, owner) => new HouseHistoryModel { OwnerId = owner, HouseId = id, EventType = default, HistoryDate = default });
        if (loaded is null)
        {
            return NotFound();
        }

        var (house, history, ownerName) = loaded.Value;
        return Ok(new SharedDetailDto<HouseDto, HouseHistoryDto, HouseMetricsDto>
        {
            Parent = houseMapper.ToDto(house),
            Children = history.ConvertAll(houseHistoryMapper.ToDto),
            Metrics = houseMetricsMapper.ToDto(HouseMetricsService.ComputeMetrics(history)),
            OwnerDisplayName = ownerName
        });
    }

    [HttpGet("{shareId}/health-profiles")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public Task<ActionResult<List<HealthProfileDto>>> GetHealthProfiles(string shareId) =>
        ReadPersonalListAsync(shareId, DomainShareCategory.Health, healthProfileRepository, healthProfileMapper);

    [HttpGet("{shareId}/health-profiles/{profileId}")]
    [ProducesResponseType(200)]
    [ProducesResponseType(404)]
    public async Task<ActionResult<SharedDetailDto<HealthProfileDto, HealthRecordDto, HealthMetricsDto>>> GetHealthProfile(string shareId, string profileId)
    {
        var loaded = await LoadSharedParentAsync(shareId, DomainShareCategory.Health, profileId, healthProfileRepository, healthRecordRepository,
            (id, owner) => new HealthRecordModel { OwnerId = owner, HealthProfileId = id, EventType = default, HistoryDate = default });
        if (loaded is null)
        {
            return NotFound();
        }

        var (profile, records, ownerName) = loaded.Value;
        return Ok(new SharedDetailDto<HealthProfileDto, HealthRecordDto, HealthMetricsDto>
        {
            Parent = healthProfileMapper.ToDto(profile),
            Children = records.ConvertAll(healthRecordMapper.ToDto),
            Metrics = healthMetricsMapper.ToDto(HealthMetricsService.ComputeMetrics(records)),
            OwnerDisplayName = ownerName
        });
    }

    // ---- match keys (creator is the book author / album artist, null for the rest) ----

    private static ItemMatchKey MovieKey(MovieModel m) => new(m.ReferenceId, m.Title, m.Year, null);
    private static ItemMatchKey TvShowKey(TvShowModel m) => new(m.ReferenceId, m.Title, m.Year, null);
    private static ItemMatchKey BookKey(BookModel m) => new(m.ReferenceId, m.Title, m.Year, m.Author);
    private static ItemMatchKey AlbumKey(AlbumModel m) => new(m.ReferenceId, m.Title, m.Year, m.Artist);
    private static ItemMatchKey VideoGameKey(VideoGameModel m) => new(m.ReferenceId, m.Title, m.Year, null);

    // ---- shared plumbing ----

    /// <summary>
    /// Loads the grant and verifies it is genuinely addressed to the caller and that the category is in
    /// scope. Returns null (caller sees a 404) for any failure, so a probing recipient can't distinguish
    /// "no such grant", "not yours" and "category not shared".
    /// </summary>
    private async Task<ShareModel?> ResolveGrantAsync(string shareId, DomainShareCategory category)
    {
        var email = this.GetEmail();
        if (email is null)
        {
            return null;
        }

        var share = await shareRepository.FindByIdAsync(shareId);
        if (share is null || !string.Equals(share.RecipientEmail, email, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return share.IncludedCategories.Contains(category) ? share : null;
    }

    private async Task<ActionResult<SharedCategoryPageDto<TDto>>> ReadAsync<TModel, TDto>(
        string shareId, DomainShareCategory category,
        IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper,
        TDto filter, PagedRequest paging,
        Func<TModel, ItemMatchKey> keyOf,
        Func<IReadOnlyList<TDto>, Task> hydrate)
        where TModel : class, IHasIdAndOwnerId
        where TDto : IReferenceLinkedDto, IHasId, new()
    {
        var share = await ResolveGrantAsync(shareId, category);
        if (share is null)
        {
            return NotFound();
        }

        var page = await repository.FindAllAsync(share.OwnerId, paging.Page, paging.PageSize, paging.Search, mapper.ToModel(filter), paging.Sort);
        var dtoPage = page.Map(mapper.ToDto);
        await hydrate(dtoPage.Items);

        return Ok(new SharedCategoryPageDto<TDto>
        {
            Items = dtoPage.Items,
            TotalCount = page.TotalCount,
            Page = page.Page,
            PageSize = page.PageSize,
            AlreadyInCollectionIds = await ComputeAlreadyOwnedIdsAsync(page.Items, repository, mapper, keyOf)
        });
    }

    /// <summary>
    /// A view-only shared list (collectibles/gear): the same paged read as the media path - honouring the
    /// recipient's search/sort/favourite/owned query - but with no reference-image hydration (these types
    /// carry their own tenant image) and no copy dedup (they're never copyable), so
    /// <see cref="SharedCategoryPageDto{TDto}.AlreadyInCollectionIds"/> stays empty. Unlike
    /// <see cref="ReadAsync{TModel,TDto}"/> the DTO need not be an <see cref="IReferenceLinkedDto"/>.
    /// </summary>
    private async Task<ActionResult<SharedCategoryPageDto<TDto>>> ReadOwnedListAsync<TModel, TDto>(
        string shareId, DomainShareCategory category,
        IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper,
        TDto filter, PagedRequest paging)
        where TModel : class, IHasIdAndOwnerId
        where TDto : IHasId, new()
    {
        var share = await ResolveGrantAsync(shareId, category);
        if (share is null)
        {
            return NotFound();
        }

        var page = await repository.FindAllAsync(share.OwnerId, paging.Page, paging.PageSize, paging.Search, mapper.ToModel(filter), paging.Sort);
        var dtoPage = page.Map(mapper.ToDto);

        return Ok(new SharedCategoryPageDto<TDto>
        {
            Items = dtoPage.Items,
            TotalCount = page.TotalCount,
            Page = page.Page,
            PageSize = page.PageSize
        });
    }

    private async Task<ActionResult<CopyResultDto<TDto>>> CopyAsync<TModel, TDto>(
        string shareId, DomainShareCategory category, string itemId,
        IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper,
        Func<TModel, string, TModel> copy,
        Func<TModel, ItemMatchKey> keyOf)
        where TModel : class, IHasIdAndOwnerId
        where TDto : new()
    {
        var share = await ResolveGrantAsync(shareId, category);
        if (share is null)
        {
            return NotFound();
        }

        // defense in depth: personal categories are never routed here, but the copyable rule lives in one place
        if (!ShareCategoryClassifier.IsCopyable(category))
        {
            return StatusCode(StatusCodes.Status403Forbidden, new { error = "This category can't be copied." });
        }

        var source = await repository.FindOneAsync(itemId, share.OwnerId);
        if (source is null)
        {
            return NotFound();
        }

        // idempotent: if the caller already owns an equivalent item, return it instead of duplicating
        var mine = await LoadOwnCollectionAsync(repository, mapper);
        var existing = SharedItemMatcher.FindMatch(keyOf(source), mine, keyOf);
        if (existing is not null)
        {
            return Ok(new CopyResultDto<TDto> { Item = mapper.ToDto(existing), AlreadyInCollection = true });
        }

        var created = await repository.CreateAsync(copy(source, this.GetUserId()));
        return Ok(new CopyResultDto<TDto> { Item = mapper.ToDto(created), AlreadyInCollection = false });
    }

    /// <summary>The sharer-side item ids on this page that the caller already has an equivalent of.</summary>
    private async Task<List<string>> ComputeAlreadyOwnedIdsAsync<TModel, TDto>(
        List<TModel> sharerItems, IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper, Func<TModel, ItemMatchKey> keyOf)
        where TModel : class, IHasIdAndOwnerId
        where TDto : new()
    {
        if (sharerItems.Count == 0)
        {
            return [];
        }

        var mine = await LoadOwnCollectionAsync(repository, mapper);
        var myKeys = mine.Select(keyOf).ToList();
        return sharerItems
            .Where(item => SharedItemMatcher.AnyMatch(keyOf(item), myKeys))
            .Select(item => item.Id!)
            .ToList();
    }

    // The caller's entire collection of this type, for dedup matching. Personal collections are small enough
    // that one unpaged read is cheaper than a per-item existence query - the same call shape Wishlist uses.
    private async Task<List<TModel>> LoadOwnCollectionAsync<TModel, TDto>(IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper)
        where TModel : class, IHasIdAndOwnerId
        where TDto : new()
    {
        var page = await repository.FindAllAsync(this.GetUserId(), 1, int.MaxValue, null, mapper.ToModel(new TDto()), null);
        return page.Items;
    }

    /// <summary>
    /// A personal category's parent items (cars/houses/health profiles), read-only, scoped to the sharer.
    /// Small collections, so an unpaged read is fine - the same call shape the media dedup path uses.
    /// </summary>
    private async Task<ActionResult<List<TDto>>> ReadPersonalListAsync<TModel, TDto>(
        string shareId, DomainShareCategory category, IDataRepository<TModel> repository, IDtoMapper<TDto, TModel> mapper)
        where TModel : class, IHasIdAndOwnerId
        where TDto : new()
    {
        var share = await ResolveGrantAsync(shareId, category);
        if (share is null)
        {
            return NotFound();
        }

        var page = await repository.FindAllAsync(share.OwnerId, 1, int.MaxValue, null, mapper.ToModel(new TDto()));
        return Ok(page.Items.ConvertAll(mapper.ToDto));
    }

    /// <summary>
    /// Resolves the grant, then loads one parent item plus its full child history, both scoped to the sharer.
    /// Returns null (caller sees a 404) for any grant/ownership failure, same as <see cref="ResolveGrantAsync"/>.
    /// The metrics computation stays in the caller so each type uses its own (static) metrics service.
    /// </summary>
    private async Task<(TParent Parent, List<TChild> Children, string? OwnerName)?> LoadSharedParentAsync<TParent, TChild>(
        string shareId, DomainShareCategory category, string parentId,
        IDataRepository<TParent> parentRepository, IDataRepository<TChild> childRepository,
        Func<string, string, TChild> makeChildFilter)
        where TParent : class, IHasIdAndOwnerId
        where TChild : class, IHasIdAndOwnerId
    {
        var share = await ResolveGrantAsync(shareId, category);
        if (share is null)
        {
            return null;
        }

        var parent = await parentRepository.FindOneAsync(parentId, share.OwnerId);
        if (parent is null)
        {
            return null;
        }

        var children = await childRepository.FindAllAsync(share.OwnerId, 1, int.MaxValue, null, makeChildFilter(parentId, share.OwnerId));
        return (parent, children.Items, share.OwnerDisplayName);
    }
}
