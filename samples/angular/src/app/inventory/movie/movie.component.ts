import { Component, OnInit, OnDestroy, ViewChild, ElementRef, inject } from '@angular/core';
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { MovieService } from 'src/app/backend/services/movie.service';
import { Movie } from 'src/app/backend/types/movie';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-movie',
  imports: [CommonModule, FormsModule],
  templateUrl: './movie.component.html'
})
export class MovieComponent extends DataComponent<Movie> implements OnInit, OnDestroy {
  protected override readonly dataService = inject(MovieService);

  @ViewChild('titleInput') titleInput= {} as ElementRef;
  @ViewChild('yearInput') yearInput= {} as ElementRef;

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
    this.yearInput.nativeElement.value = '';
  }
}
