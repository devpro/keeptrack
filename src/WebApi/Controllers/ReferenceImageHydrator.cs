using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Hydrates <see cref="IReferenceLinkedDto.ImageUrl"/> on a list of DTOs from their linked reference
/// documents with a single batched repository query. Shared by every endpoint that returns lists of
/// reference-linked items (the CRUD controllers' <c>OnListMappedAsync</c> overrides, Wishlist, Watch Next)
/// so the collect-ids/lookup/apply logic exists once; only the repository method reference is per-type.
/// </summary>
public static class ReferenceImageHydrator
{
    public static async Task HydrateAsync<TDto, TReference>(
        IReadOnlyList<TDto> dtos,
        Func<IReadOnlyCollection<string>, Task<List<TReference>>> findReferencesByIds,
        Func<TReference, string?> imageUrl)
        where TDto : IReferenceLinkedDto
        where TReference : IHasId
    {
        // distinct, non-empty ids only: unresolved items match both null (Mapperly-era writes) and ""
        // (pre-Mapperly AutoMapper writes - see the UnresolvedFilter() gotcha in CLAUDE.md).
        var ids = dtos.Select(x => x.ReferenceId).OfType<string>().Where(x => x.Length > 0).Distinct().ToList();
        if (ids.Count == 0) return;

        var references = await findReferencesByIds(ids);
        var imageUrlByReferenceId = references
            .Where(x => !string.IsNullOrEmpty(x.Id))
            .ToDictionary(x => x.Id!, imageUrl);

        foreach (var dto in dtos)
        {
            if (!string.IsNullOrEmpty(dto.ReferenceId) && imageUrlByReferenceId.TryGetValue(dto.ReferenceId, out var url))
            {
                dto.ImageUrl = url;
            }
        }
    }

    /// <summary>
    /// Reference-image hydration plus the tenant's own <c>CustomImageUrl</c> override (book/album/game only),
    /// which takes priority over the linked reference's cover. Shared by those types' list controllers, the
    /// shared-with-me reads and the wishlist so the "hydrate then override" order lives in exactly one place.
    /// </summary>
    public static async Task HydrateWithCustomOverrideAsync<TDto, TReference>(
        IReadOnlyList<TDto> dtos,
        Func<IReadOnlyCollection<string>, Task<List<TReference>>> findReferencesByIds,
        Func<TReference, string?> referenceImageUrl,
        Func<TDto, string?> customImageUrl)
        where TDto : IReferenceLinkedDto
        where TReference : IHasId
    {
        await HydrateAsync(dtos, findReferencesByIds, referenceImageUrl);
        foreach (var dto in dtos)
        {
            var custom = customImageUrl(dto);
            if (!string.IsNullOrEmpty(custom))
            {
                dto.ImageUrl = custom;
            }
        }
    }
}
