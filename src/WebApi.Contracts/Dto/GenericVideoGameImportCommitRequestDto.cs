using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The set of generic video game transaction rows the user picked in the review UI, ready to be created as
/// video games.
/// </summary>
public class GenericVideoGameImportCommitRequestDto
{
    public required List<GenericVideoGameImportCommitItemDto> Items { get; set; }
}
