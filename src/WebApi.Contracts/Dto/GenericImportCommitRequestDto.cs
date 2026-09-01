using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The set of generic-import rows the user picked in the review UI, ready to be created/merged.
/// </summary>
public class GenericImportCommitRequestDto
{
    public required List<GenericImportCommitItemDto> Items { get; set; }
}
