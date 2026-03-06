import { HttpEvent, HttpHandler, HttpRequest } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

import { BackendData } from 'src/app/backend/types/backend-data';

@Injectable({
  providedIn: 'root'
})
export class JwtInterceptorService {
  private token: string | null = null;

  intercept(req: HttpRequest<BackendData | null>, next: HttpHandler): Observable<HttpEvent<BackendData | null>> {
    if (this.token) {
      const clone = req.clone({ setHeaders: { authorization: `Bearer ${this.token}` } });
      return next.handle(clone);
    }
    return next.handle(req);
  }

  getJwtToken(): string | null {
    return this.token;
  }

  setJwtToken(token: string) {
    this.token = token;
  }

  removeJwtToken() {
    this.token = null;
  }
}
