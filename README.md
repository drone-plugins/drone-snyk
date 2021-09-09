A plugin to scan container images for vulnerabilities using snyk.

By using this plugin you agree to accept the terms and conditions set out by snyk and docker. More details can be found [here](https://snyk.io/learn/docker-security-scanning/)

# Usage

The following settings changes this plugin's behavior.

* dockerfile uri to dockerfile in repo.
* image the name of the image you wish to scan.
* snyk (optional) auth token for snyk (without this you will get 10 scans a month)

Below is an example `.drone.yml` that uses this plugin.

```yaml
kind: pipeline
name: default

steps:
- name: run drone-plugins/drone-snyk plugin
  image: drone-plugins/drone-snyk
  pull: if-not-exists
  settings:
    param1: foo
    param2: bar
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
docker run --rm -e PLUGIN_PARAM1=foo -e PLUGIN_PARAM2=bar \
  -e DRONE_COMMIT_SHA=8f51ad7884c5eb69c11d260a31da7a745e6b78e2 \
  -e DRONE_COMMIT_BRANCH=master \
  -e DRONE_BUILD_NUMBER=43 \
  -e DRONE_BUILD_STATUS=success \
  -w /drone/src \
  -v $(pwd):/drone/src \
  drone-plugins/drone-snyk
```
