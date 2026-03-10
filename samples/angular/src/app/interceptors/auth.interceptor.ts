import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { from, switchMap } from 'rxjs';
import { Auth, idToken } from '@angular/fire/auth';
import { environment } from "../../environments/environment";

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (!req.url.startsWith(environment.keepTrackApiUrl)) {
    return next(req);
  }

  return from(idToken(inject(Auth))).pipe(
    switchMap(token => {
      if (token) {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
      }
      return next(req);
    })
  );
};
