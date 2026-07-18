using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class BookStorageMapper : IStorageMapper<BookModel, Book>
{
    // IsOwned is filter-only (derived from OwnedVersions) - see MovieStorageMapper.
    [MapperIgnoreSource(nameof(BookModel.IsOwned))]
    [MapperIgnoreSource(nameof(BookModel.IsUnread))]
    public partial Book ToEntity(BookModel model);

    [MapperIgnoreTarget(nameof(BookModel.IsOwned))]
    [MapperIgnoreTarget(nameof(BookModel.IsUnread))]
    public partial BookModel ToModel(Book entity);

    public partial List<BookModel> ToModels(List<Book> entities);
}
