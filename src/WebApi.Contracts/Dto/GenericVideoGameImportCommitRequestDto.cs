using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The video game transaction rows the user picked in the review UI, ready to be created or merged.
/// </summary>
public class GenericVideoGameImportCommitRequestDto
{
    public required List<GenericVideoGameImportCommitItemDto> Items { get; set; }
}
