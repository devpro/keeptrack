import { NgModule } from '@angular/core';
import { AuthGuard } from '@angular/fire/auth-guard';
import { Routes, RouterModule } from '@angular/router';

import { CounterComponent } from './counter/counter.component';
import { FetchDataComponent } from './fetch-data/fetch-data.component';
import { HomeComponent } from './home/home.component';
import { BookComponent } from './inventory/book/book.component';
import { CarComponent } from './inventory/car/car.component';
import { MovieComponent } from './inventory/movie/movie.component';
import { TvShowComponent } from './inventory/tv-show/tv-show.component';
import { VideoGameComponent } from './inventory/video-game/video-game.component';
import { LoginComponent } from './user/login/login.component';

const routes: Routes = [
  { path: '', component: HomeComponent, pathMatch: 'full' },
  { path: 'counter', component: CounterComponent },
  { path: 'fetch-data', component: FetchDataComponent },
  { path: 'login', component: LoginComponent },
  { path: 'movies', component: MovieComponent, canActivate: [AuthGuard] }, // ref. https://github.com/angular/angularfire/blob/master/site/src/auth/route-guards.md
  { path: 'books', component: BookComponent, canActivate: [AuthGuard] },
  { path: 'cars', component: CarComponent, canActivate: [AuthGuard] },
  { path: 'tv-shows', component: TvShowComponent, canActivate: [AuthGuard] },
  { path: 'video-games', component: VideoGameComponent, canActivate: [AuthGuard] }
];

@NgModule({
  imports: [
    RouterModule.forRoot(routes, {})
  ],
  exports: [
    RouterModule
  ]
})
export class AppRoutingModule { }
