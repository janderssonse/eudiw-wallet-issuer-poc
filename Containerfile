FROM cgr.dev/chainguard/jre:latest@sha256:a6aff0af8fd0a45f06aad3e3f075e71a726b13256ea3b588f274506d05100244

USER java
WORKDIR /app

COPY target/eudiw-wallet-issuer-poc.jar ./eudiw-wallet-issuer-poc.jar

ENTRYPOINT ["java", "-jar", "./eudiw-wallet-issuer-poc.jar"]
