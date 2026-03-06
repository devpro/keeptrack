import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from 'src/environments/environment';
import { TvShow } from '../types/tv-show';
import { DataService } from './data.interface';

@Injectable({
  providedIn: 'root'
})
export class TvShowService implements DataService<TvShow> {
  constructor(private httpClient: HttpClient) {
  }

  get(id: string): Observable<TvShow> {
    return this.httpClient.get<TvShow>(`${environment.keepTrackApiUrl}/api/tv-shows/${id}`);
  }

  list(search?: string, currentPage?: number, pageSize?: number): Observable<Array<TvShow>> {
    return this.httpClient.get<Array<TvShow>>(`${environment.keepTrackApiUrl}/api/tv-shows?search=${search ?? ''}&page=${currentPage ?? 0}&pageSize=${pageSize ?? 50}`);
  }

  create(input: TvShow): Observable<TvShow> {
    return this.httpClient.post<TvShow>(`${environment.keepTrackApiUrl}/api/tv-shows`, input);
  }

  update(input: TvShow): Observable<number> {
    delete input.isEditable;
    return this.httpClient.put<number>(`${environment.keepTrackApiUrl}/api/tv-shows/${input.id}`, input);
  }

  delete(input: TvShow): Observable<number> {
    return this.httpClient.delete<number>(`${environment.keepTrackApiUrl}/api/tv-shows/${input.id}`);
  }
}
