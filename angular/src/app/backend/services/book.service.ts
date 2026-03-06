import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { environment } from 'src/environments/environment';
import { Book } from '../types/book';
import { DataService } from './data.interface';

@Injectable({
  providedIn: 'root'
})
export class BookService implements DataService<Book> {
  constructor(private httpClient: HttpClient) {
  }

  get(id: string): Observable<Book> {
    return this.httpClient.get<Book>(`${environment.keepTrackApiUrl}/api/books/${id}`);
  }

  list(search?: string, currentPage?: number, pageSize?: number): Observable<Array<Book>> {
    return this.httpClient.get<Array<Book>>(`${environment.keepTrackApiUrl}/api/books?search=${search ?? ''}&page=${currentPage ?? 0}&pageSize=${pageSize ?? 50}`);
  }

  create(input: Book): Observable<Book> {
    return this.httpClient.post<Book>(`${environment.keepTrackApiUrl}/api/books`, input);
  }

  update(input: Book): Observable<number> {
    delete input.isEditable;
    if (!input.finishedAt) {
      delete input.finishedAt;
    }
    return this.httpClient.put<number>(`${environment.keepTrackApiUrl}/api/books/${input.id}`, input);
  }

  delete(input: Book): Observable<number> {
    return this.httpClient.delete<number>(`${environment.keepTrackApiUrl}/api/books/${input.id}`);
  }
}
