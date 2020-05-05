# DDAP Common

This repo contains common code for DDAP Spring Boot applications.

To develop locally, set your dependent project (ex. [ddap-explore](https://github.com/dnastack/ddap-explore)) to use version
`0.0.1-SNAPSHOT` of `ddap-common`. Then either use your IDE to build the dependent application (both Eclipse and IntelliJ have support for resolving dependencies from the local workspace/project) or use `mvn clean install`
to install ddap-common locally before running the dependent app.

## Protos

This project has a compile-time-only dependency on DAM/IC protos.
Applications using this library *must* include their own compiled protos. This library
is not compiled with protos so that applications can use newer proto definitions (that are API compatible).
