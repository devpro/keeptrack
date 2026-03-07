import { Injectable, inject } from '@angular/core';
import { Auth, GithubAuthProvider, authState, signInWithPopup } from '@angular/fire/auth';

// see https://github.com/angular/angularfire/blob/main/docs/auth.md
@Injectable({
  providedIn: 'root'
})
export class AuthenticateService {
  private auth: Auth = inject(Auth);
  authState$ = authState(this.auth);

  // see https://firebase.google.com/docs/auth/web/github-auth
  async signInWithGitHub() {
    try {
      await signInWithPopup(this.auth, new GithubAuthProvider());
    } catch (error) {
      console.log(error);
    }
  }

  async logout() {
    await this.auth.signOut();
  }
}
