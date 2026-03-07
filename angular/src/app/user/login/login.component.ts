import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticateService } from '../services/authenticate.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  standalone: false
})
export class LoginComponent {
  constructor(private authenticateService: AuthenticateService, private router: Router) {
  }

  async signInWithGitHub() {
    await this.authenticateService.signInWithGitHub();
    await this.router.navigate(['/']);
  }
}
