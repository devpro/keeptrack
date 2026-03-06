using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/books")]
public class BookController(IMapper mapper, IBookRepository dataRepository)
    : DataCrudControllerBase<BookDto, BookModel>(mapper, dataRepository);
