import { Directive, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';

import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { DataService } from 'src/app/backend/services/data.interface';
import { BackendData } from 'src/app/backend/types/backend-data';

@Directive()
export abstract class DataComponent<T extends BackendData> implements OnInit, OnDestroy {
  userEventsSubscription: Subscription | undefined;
  items: Array<T> | undefined;
  currentPage = 1;
  pageSize = 50;

  constructor(private dataService: DataService<T>, private authenticateService: AuthenticateService) {
  }

  ngOnInit() {
    this.userEventsSubscription = this.authenticateService.authState$.subscribe(() => {
      this.load('', 1);
    });
  }

  ngOnDestroy() {
    if (this.userEventsSubscription) {
      this.userEventsSubscription.unsubscribe();
    }
  }

  load(search: string, currentPage: number, filter?: T) {
    this.currentPage = currentPage;
    this.dataService.list(search, currentPage - 1, this.pageSize, filter).subscribe({
      next: (items) => this.items = items,
      error: (error) => console.warn(error)
    });
  }

  updateCurrentPage(event: Event, newValue: number, search?: string) {
    event.preventDefault();
    if (newValue > 0) {
      this.load(search ?? '', newValue);
    }
  }

  create(item: T) {
    this.dataService.create(item).subscribe(created => {
      this.items?.push(created);
      this.resetInputFields();
    });
  }

  abstract resetInputFields(): void;

  startEditing(item: T) {
    item.isEditable = true;
  }

  cancel(item: T) {
    item.isEditable = false;

    if (!item.id) {
      return;
    }

    this.dataService.get(item.id).subscribe(existing => {
      item = existing;
    });
  }

  update(item: T) {
    this.dataService.update(item)
      .subscribe(() => item.isEditable = false);
  }

  delete(item: T) {
    this.dataService.delete(item)
      .subscribe(() => {
        if (this.items) {
          this.items.splice(this.items.findIndex(x => x.id === item.id), 1);
        }
      });
  }
}
