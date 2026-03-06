import { Injectable, OnDestroy, inject } from '@angular/core';
import { Auth, GithubAuthProvider, User, UserCredential, authState, signInWithPopup } from '@angular/fire/auth';
import { Subscription } from 'rxjs';

import { JwtInterceptorService } from './jwt-interceptor.service';

// see https://github.com/angular/angularfire/blob/main/docs/auth.md
@Injectable({
  providedIn: 'root'
})
export class AuthenticateService implements OnDestroy {
  private auth: Auth = inject(Auth);
  authState$ = authState(this.auth);
  userEventsSubscription: Subscription;

  constructor(private jwtInterceptorService: JwtInterceptorService) {
    this.userEventsSubscription = this.authState$.subscribe({
      next: (user: User | null) => {
        if (user) {
          user.getIdToken().then((token: string) => {
            jwtInterceptorService.setJwtToken(token);
          });
        }
      },
      error: (error) => console.log(error)
    });
  }

  ngOnDestroy() {
    if (this.userEventsSubscription) {
      this.userEventsSubscription.unsubscribe();
    }
  }

  signInWithGitHub() {
    // see https://firebase.google.com/docs/auth/web/github-auth
    signInWithPopup(this.auth, new GithubAuthProvider())
      .then((userCredential: UserCredential) => {
        console.log(`You (${userCredential.user.displayName}) have been successfully logged in!`);
      })
      .catch((error) => {
        console.log(error);
      });
  }

  logout() {
    this.jwtInterceptorService.removeJwtToken();
    this.auth.signOut();
  }
}
