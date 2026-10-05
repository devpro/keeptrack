# Operations

Deploying and maintaining a hosted instance.
Configuration keys are in [CONTRIBUTING.md](../CONTRIBUTING.md#configuration).

## Deployment

- Add the WebApi outbound IP addresses to the MongoDB Atlas network access list.
- Create a web app in the Firebase project and set its ids in the BlazorApp `Firebase:WebAppConfiguration:*` settings.
- Add the WebApi and BlazorApp domains to **Firebase > Authentication > Settings > Authorized domains**.
- Create a [GitHub OAuth application](https://github.com/settings/applications/new) for the [Firebase GitHub provider](https://firebase.google.com/docs/auth/web/github-auth).

Several replicas are supported (see [Architecture](architecture.md#scaling)).

## Database indexes

`scripts/mongodb-create-index.js` is idempotent, and is re-run after every change to it and after every migration script:

```bash
mongosh "mongodb+srv://<user>:<password>@<cluster>.<project>.mongodb.net/<database>" scripts/mongodb-create-index.js
```

## Migration scripts

`scripts/migrate-*.js` and the other one-off data scripts are idempotent and run the same way, each followed by the index script.
Why a shape change needs one is in [Data model](data-model.md#migrations).

## Database backups

```bash
docker run --rm -it --workdir=/data --volume "$(pwd)":/data mongo:8.2 mongodump --uri "mongodb+srv://<user>:<password>@<cluster>.<project>.mongodb.net/<database>"
docker run --rm -it --workdir=/data --volume "$(pwd)":/data mongo:8.2 mongorestore --uri "mongodb+srv://<user>:<password>@<cluster>.<project>.mongodb.net"
```

## Container image review

```bash
docker run --rm -it --entrypoint /bin/bash <repository>/<image>:<tag>
```
