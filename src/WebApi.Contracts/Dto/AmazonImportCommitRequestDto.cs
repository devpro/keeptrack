using System.Collections.Generic;

namespace Keeptrack.WebApi.Contracts.Dto;

/// <summary>
/// The set of Amazon order-history rows the user picked in the review UI, ready to be created as books.
/// </summary>
public class AmazonImportCommitRequestDto
{
    public required List<AmazonImportCommitItemDto> Items { get; set; }
}
