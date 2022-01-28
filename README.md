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
docker run -itd -e JWT_SECRET="SetThisToSomeSecureRandomString"
                -e MONGO_HOST="host.docker.internal"
                -e MONGO_PORT="27017" 
                -p 5000:5000 
                ndslabs/apiserver:python
```

### Configuration
Configuration is handled through use of environments variables, which tend to translate well between local Python
development and within Docker containers.

| Name  | Description | Default |
| ------------- | ------------- | ------------- |
| `JWT_SECRET`  | Secret to use for creating/decoding JWTs  | `thisisnotverysecret`  |
| `JWT_ALGORITHM`  | Algorithm to use for creating/decoding JWTs  | `HS256`  |
| `JWT_EXP_DELTA_MINS`  | Expiration time to use for creating/decoding JWTs (in minutes)  | `300`  |
| `KUBE_HOST`  | Hostname of the Kubernetes API server  | `localhost`  |
| `KUBE_PORT`  | Port of the Kubernetes API server  | `6443`  |
| `KUBE_TOKENPATH`  | Path within containers where the ServiceAccount token will be mounted (in-cluster only)  | `/run/secrets/kubernetes.io/serviceaccount/token`  |
| `KUBE_QPS`  | QPS to use for connection to the Kubernetes API server  | `50`  |
| `KUBE_BURST`  | Burst to use for the connection Kubernetes API server  | `100`  |
| `MONGO_HOST`  | Hostname of the Kubernetes API server  | `host.docker.internal`  |
| `MONGO_PORT`  | Port of the Kubernetes API server  | `27017`  |
| `MONGO_DATABASE`  | Port of the Kubernetes API server  | `ndslabs`  |
| `ETCD_HOST`  | Hostname of the Kubernetes API server  | `host.docker.internal`  |
| `ETCD_PORT`  | Port of the Kubernetes API server  | `4001`  |
| `ETCD_BASE_PATH`  | Port of the Kubernetes API server  | `ndslabs`  |


## Development
Clone this repo:
```bash
git clone https://github.com/nds-org/workbench-apiserver-python
```

Install Python dependencies:
```bash
pip install -r requirements.txt
```

Run the application locally (for testing):
```bash
python server.py
```

To rebuild the Docker image from source:
```bash
docker build -t ndslabs/apiserver:python .
```

## Generating CRDs
Side note: the Swagger spec provided in this project generates experimental CRDs for use in Kubernetes. These CRDs are not currently utilized by the application itself, and offered for experimentation only. CAUTION: These CRDs and the patterns surrounding them may change in the near future as we work to support them within the Python application.

See https://github.com/bodom0015/swagger-k8s-crd-codegen for details