import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';

import { BookService } from './book.service';
import { Book } from '../types/book';
import { environment } from 'src/environments/environment.dev';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('BookService', () => {
  let bookService: BookService;
  let http: HttpTestingController;

  beforeEach(() => TestBed.configureTestingModule({
    imports: [],
    providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
}));

  beforeEach(() => {
    http = TestBed.inject(HttpTestingController);
    bookService = TestBed.inject(BookService);
  });

  afterAll(() => http.verify());

  it('should list', () => {
    // fake response
    const hardcodedBooks = [{ title: 'The fellowship of the Ring' }, { title: 'The two Towers' }] as Array<Book>;

    let actualBooks: Array<Book> = [];
    bookService.list().subscribe((books: Array<Book>) => actualBooks = books);

    http.expectOne(`${environment.keepTrackApiUrl}/api/books?search=&page=0&pageSize=50`)
      .flush(hardcodedBooks);

    expect(actualBooks).toEqual(hardcodedBooks, 'The `list` method should return an array of Book wrapped in an Observable');
  });
});
