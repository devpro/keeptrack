import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { AuthenticateService } from './services/authenticate.service';
import { LoginComponent } from './login/login.component';

@NgModule({
  declarations: [LoginComponent],
  imports: [
    CommonModule
  ],
  providers: [
    AuthenticateService
  ]
})
export class UserModule { }
