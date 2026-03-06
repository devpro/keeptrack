import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';

import { environment } from 'src/environments/environment.dev';
import { MovieService } from './movie.service';
import { Movie } from '../types/movie';

describe('MovieService', () => {
  let movieService: MovieService;
  let http: HttpTestingController;

  beforeEach(() => TestBed.configureTestingModule({
    imports: [
      HttpClientTestingModule
    ]
  }));

  beforeEach(() => {
    http = TestBed.inject(HttpTestingController);
    movieService = TestBed.inject(MovieService);
  });

  afterAll(() => http.verify());

  it('should list', () => {
    // fake response
    const hardcodedMovies = [{ title: 'Terminator 1' }, { title: 'Terminator 2' }] as Array<Movie>;

    let actualMovies: Array<Movie> = [];
    movieService.list().subscribe((movies: Array<Movie>) => actualMovies = movies);

    http.expectOne(`${environment.keepTrackApiUrl}/api/movies?search=&page=0&pageSize=50`)
      .flush(hardcodedMovies);

    expect(actualMovies).toEqual(hardcodedMovies, 'The `list` method should return an array of Movie wrapped in an Observable');
  });
});
