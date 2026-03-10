import { Observable } from "rxjs";

export interface DataService<T> {
  get(id: string): Observable<T>;
  list(search?: string, currentPage?: number, pageSize?: number, filter?: T): Observable<Array<T>>;
  create(input: T): Observable<T>;
  update(input: T): Observable<number>;
  delete(input: T): Observable<number>;
}
