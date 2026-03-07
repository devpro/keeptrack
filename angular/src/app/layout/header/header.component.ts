import { Component, OnInit, OnDestroy, inject } from '@angular/core';
import { User } from '@angular/fire/auth';
import { Router, RouterLink, RouterLinkActive } from '@angular/router';
import { CommonModule } from "@angular/common";
import { Subscription } from 'rxjs';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';

@Component({
  selector: 'app-header',
  imports: [
    CommonModule,
    RouterLink,
    RouterLinkActive
  ],
  templateUrl: './header.component.html',
  styleUrls: ['./header.component.css']
})
export class HeaderComponent implements OnInit, OnDestroy {
  private authenticateService = inject(AuthenticateService);
  private router = inject(Router);

  isExpanded = false;

  user = null as User | null;
  userEventsSubscription: Subscription | undefined;

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

  async logout(event: Event) {
    event.preventDefault();
    await this.authenticateService.logout();
    await this.router.navigate(['/login']);
  }

  collapse() {
    this.isExpanded = false;
  }

  toggle() {
    this.isExpanded = !this.isExpanded;
  }

}
