# gotiny-oidc

Minimal instructions to build and run the container image produced by the included `Dockerfile`.

Build the image (from repository root):

```bash
docker build -t gotiny-oidc:latest .
```

Run with defaults (exposes container PORT 8080):

```bash
docker run --rm -p 8080:8080 gotiny-oidc:latest
```

Override the users.yaml by mounting a file or directory at `/etc/gotiny` inside the container. The Dockerfile places a default `users.yaml` at `/etc/gotiny/users.yaml`, but a bind mount will override it.

```bash
# Mount a single file
docker run --rm -p 8080:8080 -v $(pwd)/users.yaml:/etc/gotiny/users.yaml gotiny-oidc:latest

# Or mount a directory (useful when multiple config files are needed)
docker run --rm -p 8080:8080 -v $(pwd)/config:/etc/gotiny gotiny-oidc:latest
```

Environment variables supported (can be set with `-e` or in your orchestration system):

- USERS: path to the users YAML inside the container (default: `/etc/gotiny/users.yaml`)
- PORT: port the app listens on (default: `8080`)

Example setting USERS and PORT:

```bash
docker run --rm -p 9090:9090 -e PORT=9090 -e USERS=/etc/gotiny/custom-users.yaml \
  -v $(pwd)/custom-users.yaml:/etc/gotiny/custom-users.yaml gotiny-oidc:latest
```

Notes:
- The final Docker image uses `FROM scratch` and includes only the compiled binary and CA certificates. Mounting `/etc/gotiny` is the supported way to provide custom YAML.
- If you need to debug inside the image, consider building a non-scratch debug image by modifying the Dockerfile to use a lightweight base like `alpine`.
