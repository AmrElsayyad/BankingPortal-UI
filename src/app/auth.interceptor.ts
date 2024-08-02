import { ToastService } from 'angular-toastify';
import { jwtDecode } from 'jwt-decode';
import { catchError, Observable, throwError } from 'rxjs';
import { environment } from 'src/environment/environment';

import {
  HttpErrorResponse,
  HttpEvent,
  HttpHandler,
  HttpInterceptor,
  HttpRequest,
} from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private router: Router, private toastService: ToastService) {}

  intercept(
    request: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    const token = localStorage.getItem(environment.tokenName);

    if (token) {
      // Token is present, check if it's valid
      if (this.isTokenValid(token)) {
        return this.handleValidToken(request, next, token);
      } else {
        return this.handleExpiredToken(request, next);
      }
    } else {
      // No token present, allow the request as it is
      return this.handleNoToken(request, next);
    }
  }

  private isTokenValid(token: string): boolean {
    try {
      const decodedToken: any = jwtDecode(token);

      return (
        decodedToken && decodedToken.exp && decodedToken.exp * 1000 > Date.now()
      );
    } catch (error) {
      console.error('Error decoding JWT token:', error);

      return false;
    }
  }

  private handleValidToken(
    request: HttpRequest<unknown>,
    next: HttpHandler,
    token: string
  ): Observable<HttpEvent<unknown>> {
    const authRequest = request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`,
        'Access-Control-Allow-Origin': environment.origin,
      },
    });

    return next.handle(authRequest).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          // Handle 401 Unauthorized error
          console.error('Unauthorized access. Redirecting to login page...');
          localStorage.clear();
          this.router.navigate(['/login']);
          this.toastService.error('Unauthorized access. Please log in again.');
        }

        return throwError(() => error);
      })
    );
  }

  private handleExpiredToken(
    request: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    console.error('Session expired. Redirecting to login page...');
    localStorage.clear();
    this.router.navigate(['/login']);
    this.toastService.error('Session expired. Please log in again.');

    return next.handle(request);
  }

  private handleNoToken(
    request: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          // Handle 401 Unauthorized error
          console.error('Unauthorized access. Redirecting to login page...');
          this.router.navigate(['/login']);
          this.toastService.error('Unauthorized access. Please log in again.');
        }

        return throwError(() => error);
      })
    );
  }
}
