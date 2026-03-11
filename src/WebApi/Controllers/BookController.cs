using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keeptrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/books")]
public class BookController(IMapper mapper, IBookRepository dataRepository)
    : DataCrudControllerBase<BookDto, BookModel>(mapper, dataRepository);
