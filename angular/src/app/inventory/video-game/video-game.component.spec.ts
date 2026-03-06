import { TestBed, waitForAsync } from '@angular/core/testing';
import { User } from '@angular/fire/auth';
import { Observable } from 'rxjs';

import { AppModule } from 'src/app/app.module';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { VideoGameComponent } from './video-game.component';
import { VideoGameService } from 'src/app/backend/services/video-game.service';

describe('VideoGameComponent', () => {
  let fakeVideoGameService: jasmine.SpyObj<VideoGameService>;
  let fakeAuthenticateService: jasmine.SpyObj<AuthenticateService>;

  beforeEach(() => {
    const emptyUser = new Observable<User | null>();
    fakeVideoGameService = jasmine.createSpyObj('VideoGameService', ['list']);
    fakeAuthenticateService = jasmine.createSpyObj('AuthenticateService', [], { 'authState$': emptyUser });

    TestBed.configureTestingModule({
      imports: [AppModule],
      providers: [
        { provide: VideoGameService, useValue: fakeVideoGameService },
        { provide: AuthenticateService, useValue: fakeAuthenticateService }
      ]
    });
  });

  it('should listen to userEvents in ngOnInit', waitForAsync(() => {
    const fixture = TestBed.createComponent(VideoGameComponent);
    const component = fixture.componentInstance;
    component.ngOnInit();
  }));
});
