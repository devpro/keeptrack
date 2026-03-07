import { Component, ElementRef, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";

import { TvShowService } from 'src/app/backend/services/tv-show.service';
import { TvShow } from 'src/app/backend/types/tv-show';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-tv-show',
  standalone: true,
  imports: [ CommonModule, FormsModule ],
  templateUrl: './tv-show.component.html'
})
export class TvShowComponent extends DataComponent<TvShow> implements OnInit, OnDestroy {
  @ViewChild('titleInput') titleInput= {} as ElementRef;

  constructor(tvShowService: TvShowService, authenticateService: AuthenticateService) {
    super(tvShowService, authenticateService);
  }

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
  }
}
