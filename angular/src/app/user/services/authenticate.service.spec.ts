import { TestBed } from '@angular/core/testing';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { AngularFireModule } from '@angular/fire/compat';
import { AngularFireAuthModule } from '@angular/fire/compat/auth';
import { AuthenticateService } from './authenticate.service';
import { environment } from 'src/environments/environment.dev';
import { provideHttpClient, withInterceptorsFromDi } from '@angular/common/http';

describe('AuthenticateService', () => {
  let authenticateService: AuthenticateService;
  let http: HttpTestingController;

  beforeEach(() => TestBed.configureTestingModule({
    imports: [
      AngularFireModule.initializeApp(environment.firebase),
      AngularFireAuthModule],
    providers: [provideHttpClient(withInterceptorsFromDi()), provideHttpClientTesting()]
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
