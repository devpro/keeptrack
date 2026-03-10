import { TestBed } from '@angular/core/testing';
import { LoginComponent } from './login.component';
import { AuthenticateService } from '../services/authenticate.service';

describe('LoginComponent', () => {

  const fakeAuthenticateService = jasmine.createSpyObj('AuthenticateService', ['signInWithGitHub']);

  beforeEach(() => TestBed.configureTestingModule({
    imports: [],
    providers: [
      { provide: AuthenticateService, useValue: fakeAuthenticateService }
    ]
  }));

  beforeEach(() => {
    fakeAuthenticateService.signInWithGitHub.calls.reset();
  });

  it('should have a title', () => {
    const fixture = TestBed.createComponent(LoginComponent);

    // when we trigger the change detection
    fixture.detectChanges();

    // then we should have a title
    const element = fixture.nativeElement;
    expect(element.querySelector('button')).not.toBeNull('The template should have a `h1` tag');
  });
});
