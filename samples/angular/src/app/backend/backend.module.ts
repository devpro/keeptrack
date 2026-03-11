import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MovieService } from './services/movie.service';
import { CarHistoryService } from './services/car-history.service';

@NgModule({
  declarations: [],
  imports: [
    CommonModule
  ],
  providers: [
    CarHistoryService,
    MovieService
  ]
})
export class BackendModule { }
