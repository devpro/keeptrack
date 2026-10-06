using Keeptrack.Common.System;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Hydrates <see cref="IReferenceLinkedDto.ImageUrl"/> on a list of DTOs from their linked references, in one batched query.
/// Shared by every endpoint listing reference-linked items (the CRUD controllers, Wishlist, Watch Next), only the repository method varying per type.
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
        // distinct non-empty ids, since an unlinked item holds null or, in older documents, "" (see docs/data-model.md)
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
    /// Cover hydration followed by the tenant's own <c>CustomImageUrl</c> (books, albums, games), which takes priority over the reference's cover.
    /// Shared by those types' list controllers, the shared reads and the wishlist, so the order is written once.
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
