import { Routes } from '@angular/router';
import { AuthGuard } from '@angular/fire/auth-guard';

import { HomeComponent } from './home/home.component';
import { BookComponent } from './inventory/book/book.component';
import { CarComponent } from './inventory/car/car.component';
import { MovieComponent } from './inventory/movie/movie.component';
import { TvShowComponent } from './inventory/tv-show/tv-show.component';
import { VideoGameComponent } from './inventory/video-game/video-game.component';
import { LoginComponent } from './user/login/login.component';

export const routes: Routes = [
  { path: '', component: HomeComponent, pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'movies', component: MovieComponent, canActivate: [AuthGuard] },
  { path: 'books', component: BookComponent, canActivate: [AuthGuard] },
  { path: 'cars', component: CarComponent, canActivate: [AuthGuard] },
  { path: 'tv-shows', component: TvShowComponent, canActivate: [AuthGuard] },
  { path: 'video-games', component: VideoGameComponent, canActivate: [AuthGuard] }
];
