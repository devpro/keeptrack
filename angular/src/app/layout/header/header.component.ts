import { Component, OnInit, OnDestroy } from '@angular/core';
import { User } from '@angular/fire/auth';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';

import { AuthenticateService } from 'src/app/user/services/authenticate.service';

@Component({
  selector: 'app-header',
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit, OnDestroy {
  isExpanded = false;

  user = null as User | null;
  userEventsSubscription: Subscription | undefined;

  constructor(private authenticateService: AuthenticateService, private router: Router) { }

  ngOnInit() {
    this.userEventsSubscription = this.authenticateService.authState$.subscribe({
      next: (user: User | null) => this.user = user,
      error: (error) => console.log(error)
    });
  }

  ngOnDestroy() {
    if (this.userEventsSubscription) {
      this.userEventsSubscription.unsubscribe();
    }
  }

  logout(event: Event) {
    event.preventDefault();
    this.authenticateService.logout();
    this.router.navigate(['/login']);
  }

  collapse() {
    this.isExpanded = false;
  }

  toggle() {
    this.isExpanded = !this.isExpanded;
  }

}
