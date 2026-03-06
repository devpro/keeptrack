import { Component, OnInit, OnDestroy, ViewChild, ElementRef } from '@angular/core';

import { MovieService } from 'src/app/backend/services/movie.service';
import { Movie } from 'src/app/backend/types/movie';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-movie',
  templateUrl: './movie.component.html',
  styleUrls: ['./movie.component.css']
})
export class MovieComponent extends DataComponent<Movie> implements OnInit, OnDestroy {
  @ViewChild('titleInput') titleInput= {} as ElementRef;
  @ViewChild('yearInput') yearInput= {} as ElementRef;

  constructor(movieService: MovieService, authenticateService: AuthenticateService) {
    super(movieService, authenticateService);
  }

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
    this.yearInput.nativeElement.value = '';
  }
}
