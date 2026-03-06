import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticateService } from '../services/authenticate.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {

  constructor(private authenticateService: AuthenticateService, private router: Router) {
  }

  signInWithGitHub() {
    this.authenticateService.signInWithGitHub();
    this.router.navigate(['/']);
  }

}
