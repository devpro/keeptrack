# Operations

## Deployment

- Add the web api outbound IP addresses to the MongoDB Atlas cluster
- Create web project in Firebase and grab ids to be set to environment.ts file
- Add the web api and blazor app to Firebase domains
- Create a GitHub OAuth application ([firebase.google.com](https://firebase.google.com/docs/auth/web/github-auth),
  [github.com](https://github.com/settings/applications/new))

## Database optimization

- Create database indexes

  ```bash
  docker run --rm --link mongodb -v "$(pwd)/scripts":/home/scripts mongo:8.2 bash -c "mongo mongodb://mongodb:27017/keeptrack /home/scripts/mongo-create-index.js"
  ```

## Database backups

- Dump MongoDB database

```bash
docker run --rm -it --workdir=/data --volume $(pwd):/data mongo:8.2 /bin/sh -c "mongodump --uri mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.<PROJECT>.mongodb.net/test"
```

- Restore MongoDB database

```bash
docker run --rm -it --workdir=/data --volume $(pwd):/data mongo:8.2 /bin/sh -c "mongorestore --uri mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.<PROJECT>.mongodb.net"
```

## Container image review

- Open a shell on an image:

```bash
docker run --rm -it --entrypoint /bin/bash <REPO>/<IMAGE>:<TAG>
```
