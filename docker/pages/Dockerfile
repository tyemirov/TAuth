# syntax=docker/dockerfile:1

FROM scratch AS pages-source

COPY docs/ /
COPY web/tauth.js /tauth.js

FROM scratch AS pages

COPY --from=pages-source / /
