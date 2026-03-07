import { Component, OnInit, OnDestroy, ElementRef, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { BookService } from 'src/app/backend/services/book.service';
import { Book } from 'src/app/backend/types/book';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-book',
  standalone: true,
  imports: [ CommonModule, FormsModule ],
  templateUrl: './book.component.html'
})
export class BookComponent extends DataComponent<Book> implements OnInit, OnDestroy {
  @ViewChild('titleInput') titleInput = {} as ElementRef;
  @ViewChild('authorInput') authorInput = {} as ElementRef;
  @ViewChild('seriesInput') seriesInput = {} as ElementRef;
  @ViewChild('searchInput') searchInput = {} as ElementRef;

  constructor(bookService: BookService, authenticateService: AuthenticateService) {
    super(bookService, authenticateService);
  }

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
    this.authorInput.nativeElement.value = '';
    this.seriesInput.nativeElement.value = '';
  }
}
