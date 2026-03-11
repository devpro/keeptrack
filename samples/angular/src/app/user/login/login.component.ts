import { Component, inject } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticateService } from '../services/authenticate.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html'
})
export class LoginComponent {
  private authenticateService = inject(AuthenticateService);
  private router = inject(Router);

  async signInWithGitHub() {
    await this.authenticateService.signInWithGitHub();
    await this.router.navigate(['/']);
  }
}
