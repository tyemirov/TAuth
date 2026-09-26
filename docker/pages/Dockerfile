# syntax=docker/dockerfile:1

FROM scratch AS pages-source

COPY docs/ /
COPY web/tauth.js /tauth.js
COPY web/app/ /app/

FROM scratch AS pages

COPY --from=pages-source / /
