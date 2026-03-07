import { Component, ElementRef, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { CommonModule } from "@angular/common";
import { FormsModule } from "@angular/forms";

import { VideoGameService } from 'src/app/backend/services/video-game.service';
import { VideoGame } from 'src/app/backend/types/video-game';
import { AuthenticateService } from 'src/app/user/services/authenticate.service';
import { DataComponent } from '../base/data.component';

@Component({
  selector: 'app-video-game',
  imports: [CommonModule, FormsModule],
  templateUrl: './video-game.component.html'
})
export class VideoGameComponent extends DataComponent<VideoGame> implements OnInit, OnDestroy {
  @ViewChild('titleInput') titleInput = {} as ElementRef;
  @ViewChild('platformInput') platformInput= {} as ElementRef;
  @ViewChild('stateInput') stateInput= {} as ElementRef;

  constructor(videoGameService: VideoGameService, authenticateService: AuthenticateService) {
    super(videoGameService, authenticateService);
  }

  resetInputFields() {
    this.titleInput.nativeElement.value = '';
    this.platformInput.nativeElement.value = '';
    this.stateInput.nativeElement.value = '';
  }
}
