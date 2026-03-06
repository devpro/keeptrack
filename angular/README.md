# Keeptrack Angular frontend application

This project was generated with [Angular CLI](https://github.com/angular/angular-cli).

## Local setup

### Requirements

* [NPM (Node.js)](https://nodejs.org/en/)
* [Angular CLI](https://cli.angular.io/): `npm install -g @angular/cli`
* [Firebase CLI](https://www.npmjs.com/package/firebase-tools): `npm install -g firebase-tools`

### Configuration

* Create a file `src/environments/environment.dev.ts` and update it (this file is not purposed to node save secret values)
  * Open your project in the [Firebase console](https://console.firebase.google.com/), go in the properties pages (General tab), inside "Your apps" part you'll have all Firebase information
  * Get the value from your local API URL (`https://localhost:5011`)

### Installation of package

Run `npm install` to load all dependencies.

### Development server

Run `npm start` for a dev server. Navigate to `http://localhost:4200/`. The app will automatically reload if you change any of the source files.

_Warning_: you may encounter CORS issues while testing with Firefox, use Chrome for local debug

### Code scaffolding

Run `ng generate component <folder>/<component-name> --module=<module-name>` to generate a new component. You can also use `ng generate directive|pipe|service|class|guard|interface|enum|module`.

### Build

Run `npm run build` to build the project. The build artifacts will be stored in the `dist/` directory. Use the `--prod` flag for a production build.

### Running unit tests

Run `npm run test` to execute the unit tests via [Karma](https://karma-runner.github.io).

### Running end-to-end tests

Run `npm run e2e` to execute the end-to-end tests via [Protractor](http://www.protractortest.org/).

### Running linter

Run `npm run lint` to validate source code standards.

### Further help

To get more help on the Angular CLI use `ng help` or go check out the [Angular CLI README](https://github.com/angular/angular-cli/blob/master/README.md).

### Update procedure

* Update NPM: `npm install --global npm`
* Follow procedure described by [update.angular.io](https://update.angular.io/): `ng update <component>`

### Firebase guide

* [Getting started with Firebase Authentication](https://github.com/angular/angularfire/blob/master/docs/auth/getting-started.md)
* [angularfire/samples/compat](https://github.com/angular/angularfire/tree/master/samples/compat)

### Graphic design

* [Bootstrap v4.6](https://getbootstrap.com/docs/4.6/getting-started/introduction/)
* [Font Awesome v4.7.0](https://fontawesome.bootstrapcheatsheets.com/)
