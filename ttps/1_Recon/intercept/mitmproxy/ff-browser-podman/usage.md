close firefox if it's already running.

If you have podman:

```sh
make build
make run
```

If you prefer docker:

```sh
make build DOCKER=docker
make run DOCKER=docker
```