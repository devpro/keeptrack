using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.WebApi.Controllers;

/// <summary>
/// Hydrates <see cref="IReferenceLinkedDto.ImageUrl"/> on a list page of DTOs from their linked reference
/// documents. Shared by every reference-bearing controller's <c>OnListMappedAsync</c> override so the
/// collect-ids/apply-urls logic exists once; only the repository call in between is per-type.
/// </summary>
public static class ReferenceImageHydrator
{
    /// <summary>
    /// The distinct, non-empty <c>ReferenceId</c>s of a page - the batch key set for a single
    /// <c>FindByIdsAsync</c> query instead of one lookup per item.
    /// </summary>
    public static IReadOnlyCollection<string> CollectReferenceIds<TDto>(IEnumerable<TDto> dtos)
        where TDto : IReferenceLinkedDto
        => dtos.Select(x => x.ReferenceId).OfType<string>().Where(x => x.Length > 0).Distinct().ToList();

    public static void Apply<TDto>(IEnumerable<TDto> dtos, IReadOnlyDictionary<string, string?> imageUrlByReferenceId)
        where TDto : IReferenceLinkedDto
    {
        foreach (var dto in dtos)
        {
            if (!string.IsNullOrEmpty(dto.ReferenceId) && imageUrlByReferenceId.TryGetValue(dto.ReferenceId, out var imageUrl))
            {
                dto.ImageUrl = imageUrl;
            }
        }
    }
}
