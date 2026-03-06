import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from 'src/environments/environment';
import { VideoGame } from '../types/video-game';
import { DataService } from './data.interface';

@Injectable({
  providedIn: 'root'
})
export class VideoGameService implements DataService<VideoGame> {
  constructor(private httpClient: HttpClient) {
  }

  get(id: string): Observable<VideoGame> {
    return this.httpClient.get<VideoGame>(`${environment.keepTrackApiUrl}/api/video-games/${id}`);
  }

  list(search?: string, currentPage?: number, pageSize?: number, filter?: VideoGame): Observable<Array<VideoGame>> {
    return this.httpClient.get<Array<VideoGame>>(`${environment.keepTrackApiUrl}/api/video-games?search=${search ?? ''}&platform=${filter?.platform ?? ''}&state=${filter?.state ?? ''}&page=${currentPage ?? 0}&pageSize=${pageSize ?? 50}`);
  }

  create(input: VideoGame): Observable<VideoGame> {
    return this.httpClient.post<VideoGame>(`${environment.keepTrackApiUrl}/api/video-games`, input);
  }

  update(input: VideoGame): Observable<number> {
    delete input.isEditable;
    if (!input.finishedAt) {
      delete input.finishedAt;
    }
    if (!input.releasedAt) {
      delete input.releasedAt;
    }
    return this.httpClient.put<number>(`${environment.keepTrackApiUrl}/api/video-games/${input.id}`, input);
  }

  delete(input: VideoGame): Observable<number> {
    return this.httpClient.delete<number>(`${environment.keepTrackApiUrl}/api/video-games/${input.id}`);
  }
}
