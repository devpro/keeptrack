import { TestBed, waitForAsync } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';
import { HeaderComponent } from './header.component';
import { AppModule } from 'src/app/app.module';

describe('HeaderComponent', () => {

  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      imports: [AppModule, RouterTestingModule]
    });
  }));

  it('display a link to go the login', () => {
    const fixture = TestBed.createComponent(HeaderComponent);
    const element = fixture.nativeElement;
    fixture.detectChanges();

    fixture.componentInstance.user = null;
    fixture.detectChanges();

    const button = element.querySelector('a[href="/login"]');
    expect(button).not.toBeNull('You should have an `a` element to display the link to the login. Maybe you forgot to use `routerLink`?');
    expect(button.textContent).toContain('Login', 'The link should have a text');
  });
});
