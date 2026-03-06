import { TestBed, waitForAsync } from '@angular/core/testing';
import { User } from '@angular/fire/auth';
import { Observable } from 'rxjs';

import { AppModule } from 'src/app/app.module';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { MovieComponent } from './movie.component';
import { MovieService } from 'src/app/backend/services/movie.service';

describe('MovieComponent', () => {
  let fakeMovieService: jasmine.SpyObj<MovieService>;
  let fakeAuthenticateService: jasmine.SpyObj<AuthenticateService>;

  beforeEach(() => {
    const emptyUser = new Observable<User | null>();
    fakeMovieService = jasmine.createSpyObj('MovieService', ['list']);
    fakeAuthenticateService = jasmine.createSpyObj('AuthenticateService', [], { 'authState$': emptyUser });

    TestBed.configureTestingModule({
      imports: [AppModule],
      providers: [
        { provide: MovieService, useValue: fakeMovieService },
        { provide: AuthenticateService, useValue: fakeAuthenticateService }
      ]
    });
  });

  it('should listen to userEvents in ngOnInit', waitForAsync(() => {
    const fixture = TestBed.createComponent(MovieComponent);
    const component = fixture.componentInstance;
    component.ngOnInit();
  }));
});
