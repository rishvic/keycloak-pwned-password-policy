ARG KEYCLOAK_VERSION=26.6.2
ARG MAVEN_IMAGE=3.9.15-eclipse-temurin-21

FROM maven:${MAVEN_IMAGE} AS builder

ARG KEYCLOAK_VERSION
WORKDIR /usr/src/build
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -B -ntp -Dkeycloak.version=${KEYCLOAK_VERSION} dependency:go-offline
COPY src src
RUN ./mvnw -B -ntp -Dkeycloak.version=${KEYCLOAK_VERSION} package

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS final

COPY --from=builder /usr/src/build/target/keycloak-pwned-password-policy-*.jar /opt/keycloak/providers
RUN /opt/keycloak/bin/kc.sh build
