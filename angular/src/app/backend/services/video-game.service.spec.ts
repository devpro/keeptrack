import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { VideoGameService } from './video-game.service';
import { VideoGame } from '../types/video-game';
import { environment } from 'src/environments/environment.dev';

describe('VideoGameService', () => {
  let service: VideoGameService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule
      ]
    });
    http = TestBed.inject(HttpTestingController);
    service = TestBed.inject(VideoGameService);
  });

  afterAll(() => http.verify());

  it('should list', () => {
    // fake response
    const fake = [{ title: 'Final Fantasy VII' }, { title: 'Resident Evil' }] as Array<VideoGame>;

    let actual: Array<VideoGame> = [];
    service.list().subscribe((movies: Array<VideoGame>) => actual = movies);

    http.expectOne(`${environment.keepTrackApiUrl}/api/video-games?search=&platform=&state=&page=0&pageSize=50`)
      .flush(fake);

    expect(actual).toEqual(fake, 'The `list` method should return an array of TV Shows wrapped in an Observable');
  });
});
