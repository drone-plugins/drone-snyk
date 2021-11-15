A plugin to scan container images for vulnerabilities using snyk.

By using this plugin you agree to accept the terms and conditions set out by snyk and docker. More details can be found [here](https://snyk.io/learn/docker-security-scanning/)

# Usage

The following settings changes this plugin's behavior.

* dockerfile uri to dockerfile in repo.
* image the name of the image you wish to scan.
* snyk (optional) auth token for snyk (without this you will get 10 scans a month)
* severity threshold can be set the limit the results return, low, medium, high & critical are acceptable inputs

> Either a docker username/passport or Snyk token can be used for authentication

> Notice: Be aware that the Docker plugin currently requires privileged capabilities, otherwise the integrated Docker daemon is not able to start.

Below is an example `.drone.yml` that uses this plugin using snyk auth

```yaml
kind: pipeline
name: default

steps:
- name: scan
  image: drone-plugins/drone-snyk
  pull: if-not-exists
  privileged: true
  settings:
      dockerfile: link to dockerfile in repo
      image: image name
      snyk_token:
        from_secret: snyk
      fail_on_issues: false // step won't fail if set to false
```
Below is an example `.drone.yml` that uses this plugin using docker auth

```yaml
kind: pipeline
name: default

steps:
- name: scan
  image: drone-plugins/drone-snyk
  pull: if-not-exists
  privileged: true
  settings:
      dockerfile: link to dockerfile in repo
      image: image name
      username:
        from_secret: username
      password:
        from_secret: password
```
# Additional Settings
```text
REGISTRY // docker registry address
USERNAME // Docker registry username
PASSWORD // Docker registry password
EMAIL    // Docker registry email
CONFIG   // Docker Auth Config

REGISTRY            // Docker registry
MIRROR              // Docker registry mirror
INSECURE            // Docker daemon enable insecure registries
STORAGE_DRIVER      // Docker daemon storage driver
STORAGE_PATH        // Docker daemon storage path
DAEMON_OFF          // Docker daemon is disabled (already running)
DEBUG               // Docker daemon started in debug mode
BIP                 // Docker daemon network bridge IP address
CUSTOM_DNS          // Docker daemon dns server
CUSTOM_DNS_SEARCH   // Docker daemon dns search domain
MTU                 // Docker daemon mtu setting
IPV6                // Docker daemon IPv6 networking
EXPERIMENTAL        // Docker daemon enable experimental mode
```

# Building

Build the plugin binary:

```text
scripts/build.sh
```

Build the plugin image:

```text
docker build -t drone-plugins/drone-snyk -f docker/Dockerfile .
```

# Testing

Execute the plugin from your current working directory:

```text
docker run --rm -e PLUGIN_IMAGE=image -e PLUGIN_DOCKERFILE=dockerfile -e PLUGIN_USERNAME=username -e PLUGIN_PASSWORD=password --privileged=true  \
  -e DRONE_COMMIT_SHA=8f51ad7884c5eb69c11d260a31da7a745e6b78e2 \
  -e DRONE_COMMIT_BRANCH=master \
  -e DRONE_BUILD_NUMBER=43 \
  -e DRONE_BUILD_STATUS=success \
  -w /drone/src \
  -v $(pwd):/drone/src \
  drone-plugins/drone-snyk
```
