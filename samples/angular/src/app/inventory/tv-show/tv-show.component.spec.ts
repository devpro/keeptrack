import { TestBed, waitForAsync } from '@angular/core/testing';
import { User } from '@angular/fire/auth';
import { Observable } from 'rxjs';

import { AppModule } from 'src/app/app.module';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { TvShowComponent } from './tv-show.component';
import { TvShowService } from 'src/app/backend/services/tv-show.service';

describe('TvShowComponent', () => {
  let fakeTvShowService: jasmine.SpyObj<TvShowService>;
  let fakeAuthenticateService: jasmine.SpyObj<AuthenticateService>;

  beforeEach(() => {
    const emptyUser = new Observable<User | null>();
    fakeTvShowService = jasmine.createSpyObj<TvShowService>('TvShowService', ['list']);
    fakeAuthenticateService = jasmine.createSpyObj<AuthenticateService>('AuthenticateService', [], { 'authState$': emptyUser });

    TestBed.configureTestingModule({
      imports: [AppModule],
      providers: [
        { provide: TvShowService, useValue: fakeTvShowService },
        { provide: AuthenticateService, useValue: fakeAuthenticateService }
      ]
    });
  });

  it('should listen to userEvents in ngOnInit', waitForAsync(() => {
    const fixture = TestBed.createComponent(TvShowComponent);
    const component = fixture.componentInstance;
    component.ngOnInit();
  }));
});
