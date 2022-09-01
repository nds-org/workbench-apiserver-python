# Workbench API server rewritten in Python
This project utilizes a Swagger spec compatible work Workbench V1.

## Prerequisites
* A running MongoDB (by default)
* Or a running etcd (legacy)

## Usage
This project offers a fairly standard Docker image that can be built and run using common patterns.
With Docker, there is no need to clone the source in order to run the full application.

To run the pre-built Docker image:
```bash
$ docker run -itd -e KEYCLOAK_HOST="https://gateway.docker.internal/auth" \
                  -e MONGO_URI="mongodb://gateway.docker.internal:27017/ndslabs?authSource=admin" \
                  -p 5000:5000 \
                  ndslabs/apiserver:python
```

### Configuration
These options can be changed by adjusting either `env/backend.json` or using environment variables.

If no environment variables are provided, then the values in `backend.json` will be used.
If environment variables are provided, then those will be used directly.

Below are the configuration options offered by the application:

| EnvVar                     | JSON Path                      | Description                                                                       | Default                                                            |
|----------------------------|--------------------------------|-----------------------------------------------------------------------------------|--------------------------------------------------------------------|
| `BACKEND_CFG_PATH`         | --                             | Set the location of `backend.json`                                                | `./env/backend.json`                                               |
| `FRONTEND_CFG_PATH`        | --                             | Set the location of `frontend.json`                                               | `./env/frontend.json`                                              |
| `DEBUG`                    | `debug`                        | If true, enable Debug mode (verbose output + live reload)                         | `false`                                                            |
| `DOMAIN`                   | `domain`                       | Domain suffix to use for creating ingress rules                                   | `kubernetes.docker.internal`                                       |
| `KUBE_WORKBENCH_SINGLEPOD` | `singlepod`                    | If true, run each workbench app as a single pod                                   | `false`                                                            |
| `KUBE_PVC_STORAGECLASS`    | `storage_class`                | StorageClass for created userapp volumes                                          | `ndslabs`                                                          |
| `KUBE_WORKBENCH_NAMESPACE` | `namespace`                    | The namespace to use for created resources (if empty, create per-user namespaces) | `default`                                                          |
| `KUBE_RESOURCE_PREFIX`     | `resource_prefix`              | If given, prepend this prefix to all resource names created by the server         | `""`                                                               |
| `SWAGGER_URL`              | `swagger_url`                  | Path to the Swagger spec to use to run the application                            | `openapi/swagger-v1.yml`                                           |
| `INSECURE_SSL_VERIFY`      | `insecure_ssl_verify`          | If false, skip verification of insecure SSL requests                              | `true`                                                             |
| `KEYCLOAK_HOST`            | `keycloak.hostname`            | Hostname of the Keycloak instance to use                                          | `https://kubernetes.docker.internal/auth`                          |
| `KEYCLOAK_REALM`           | `keycloak.realmName`           | Realm name to use for OIDC discovery                                              | `workbench-dev`                                                    |
| `KEYCLOAK_CLIENT_ID`       | `keycloak.clientId`            | Client ID (name) of the Client in keycloak                                        | `workbench-local`                                                  |
| `KEYCLOAK_CLIENT_SECRET`   | `keycloak.clientSecret`        | Client Secret for the client above (not needed for "public" clients)              | `""`                                                               |
| `MONGO_URI`                | `mongo.uri`                    | URI of the MongoDB cluster to use                                                 | `mongodb://gateway.docker.internal:27017/ndslabs?authSource=admin` |
| `MONGO_DB`                 | `mongo.db`                     | Database name to use                                                              | `ndslabs`                                                          |
| `OAUTH_USERINFO_URL`       | `oauth.userinfoUrl`            | URL to the auth userinfo endpoint                                                 | `openapi/swagger-v1.yml`                                           |

#### Experimental
TODOs and/or proposed or currently unused config items.


| EnvVar                     | JSON Path                      | Description                                                                | Default        |
|----------------------------|--------------------------------|----------------------------------------------------------------------------|----------------|
| --                         | `timeout`                      | Default startup timeout for userapps                                       | `30`           |
| --                         | `inactivity_timeout`           | Default inactivity timeout for userapps                                    | `30`           |
| --                         | `specs.repo`                   | Repo to import appspecs                                                    | `30`           |
| --                         | `specs.branch`                 | Branch to import appspecs                                                  | `30`           |
| --                         | `storage.home.claim_suffix`    | Suffix to append to the names of user "home" PVCs                          | `-home`        |
| --                         | `storage.home.storage_class`   | Removed: Replaced by `storage_class`                                       | `nfs`          |
| --                         | `storage.shared.enabled`       | If true, mount shared storage to each user pod                             | `false`        |
| --                         | `storage.shared.read_only`     | If true, mount shared storage as ReadOnly                                  | `true`         |
| --                         | `storage.shared.storage_class` | StorageClass to use when creating shared storage volume                    | `nfs`          |
| --                         | `storage.shared.volume_path`   | Path within each container to mount the shared storage volume              | `/tmp/shared`  |
| --                         | `userapps.ingress.annotations` | Add additional annotations to add to the created ingress rules (e.g. auth) | `{}`           |

## Development
Clone this repo:
```bash
$ git clone https://github.com/nds-org/workbench-apiserver-python
```

Install Python dependencies:
```bash
$ pip install -r requirements.txt
```

Run the application locally (for testing):
```bash
$ python server.py
```

To rebuild the Docker image from source:
```bash
$ docker build -t ndslabs/apiserver:python .
```

## Generating CRDs
Side note: the Swagger spec provided in this project generates experimental CRDs for use in Kubernetes. These CRDs are not currently utilized by the application itself, and offered for experimentation only. CAUTION: These CRDs and the patterns surrounding them may change in the near future as we work to support them within the Python application.

See https://github.com/bodom0015/swagger-k8s-crd-codegen for details

## Importing Specs
In the `jobs/` folder is a small script/image that can be used to populate the database using a folder of spec JSONs.

To see a full list of available applications, see https://github.com/nds-org/ndslabs-specs

If you modify the script locally, you can rebuild the image:
```bash
$ docker build -t YOUR_USERNAME/specloader .
```

NOTE: You **must** push the image to a public location to use it within your cluster
```bash
$ docker push YOUR_USERNAME/specloader
```
