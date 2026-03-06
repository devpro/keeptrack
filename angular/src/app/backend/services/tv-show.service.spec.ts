import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';

import { environment } from 'src/environments/environment.dev';
import { TvShow } from '../types/tv-show';
import { TvShowService } from './tv-show.service';

describe('TvShowService', () => {
  let service: TvShowService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule
      ]
    });
    http = TestBed.inject(HttpTestingController);
    service = TestBed.inject(TvShowService);
  });

  afterAll(() => http.verify());

  it('should list', () => {
    // fake response
    const fake = [{ title: 'Friends' }, { title: 'ER' }] as Array<TvShow>;

    let actual: Array<TvShow> = [];
    service.list().subscribe((movies: Array<TvShow>) => actual = movies);

    http.expectOne(`${environment.keepTrackApiUrl}/api/tv-shows?search=&page=0&pageSize=50`)
      .flush(fake);

    expect(actual).toEqual(fake, 'The `list` method should return an array of TV Shows wrapped in an Observable');
  });

});
