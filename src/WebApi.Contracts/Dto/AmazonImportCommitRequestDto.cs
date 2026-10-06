using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The Amazon order rows the user picked in the review UI, ready to be created or merged.
/// </summary>
public class AmazonImportCommitRequestDto
{
    public required List<AmazonImportCommitItemDto> Items { get; set; }
}
