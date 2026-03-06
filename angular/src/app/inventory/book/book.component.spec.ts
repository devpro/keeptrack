import { TestBed, waitForAsync } from '@angular/core/testing';
import { User } from '@angular/fire/auth';
import { Observable } from 'rxjs';

import { AppModule } from 'src/app/app.module';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { BookComponent } from './book.component';
import { BookService } from 'src/app/backend/services/book.service';

describe('BookComponent', () => {
  let fakeBookService: jasmine.SpyObj<BookService>;
  let fakeAuthenticateService: jasmine.SpyObj<AuthenticateService>;

  beforeEach(() => {
    const emptyUser = new Observable<User | null>();
    fakeBookService = jasmine.createSpyObj('BookService', ['list']);
    fakeAuthenticateService = jasmine.createSpyObj('AuthenticateService', [], { 'authState$': emptyUser });

    TestBed.configureTestingModule({
      imports: [AppModule],
      providers: [
        { provide: BookService, useValue: fakeBookService },
        { provide: AuthenticateService, useValue: fakeAuthenticateService }
      ]
    });
  });

  it('should listen to userEvents in ngOnInit', waitForAsync(() => {
    const fixture = TestBed.createComponent(BookComponent);
    const component = fixture.componentInstance;
    component.ngOnInit();
  }));
});
