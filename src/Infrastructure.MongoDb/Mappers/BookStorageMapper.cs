using System.Collections.Generic;
using Keeptrack.Domain.Models;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Riok.Mapperly.Abstractions;

namespace Keeptrack.Infrastructure.MongoDb.Mappers;

[Mapper]
[UseStaticMapper(typeof(CommonStorageMappings))]
public partial class BookStorageMapper : IStorageMapper<BookModel, Book>
{
    public partial Book ToEntity(BookModel model);

    public partial BookModel ToModel(Book entity);

    public partial List<BookModel> ToModels(List<Book> entities);
}
