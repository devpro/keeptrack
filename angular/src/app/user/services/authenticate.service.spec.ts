import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { AngularFireModule } from '@angular/fire/compat';
import { AngularFireAuthModule } from '@angular/fire/compat/auth';
import { AuthenticateService } from './authenticate.service';
import { environment } from 'src/environments/environment.dev';
import { AppModule } from 'src/app/app.module';

describe('AuthenticateService', () => {
  let authenticateService: AuthenticateService;
  let http: HttpTestingController;

  beforeEach(() => TestBed.configureTestingModule({
    imports: [
      HttpClientTestingModule,
      AngularFireModule.initializeApp(environment.firebase),
      AngularFireAuthModule,
      AppModule
    ]
  }));

  beforeEach(() => {
    http = TestBed.inject(HttpTestingController);
    authenticateService = TestBed.inject(AuthenticateService);
  });

  afterAll(() => http.verify());

  it('should logout', () => {
    authenticateService.logout();
  });
});
