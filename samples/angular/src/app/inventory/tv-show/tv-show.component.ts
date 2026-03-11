import { Component, ElementRef, OnDestroy, OnInit, ViewChild, inject } from '@angular/core';
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";
import { TvShowService } from 'src/app/backend/services/tv-show.service';
import { TvShow } from 'src/app/backend/types/tv-show';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-tv-show',
  imports: [CommonModule, FormsModule],
  templateUrl: './tv-show.component.html'
})
export class TvShowComponent extends DataComponent<TvShow> implements OnInit, OnDestroy {
  protected override readonly dataService = inject(TvShowService);

  @ViewChild('titleInput') titleInput= {} as ElementRef;

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
  }
}
