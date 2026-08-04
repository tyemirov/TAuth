# syntax=docker/dockerfile:1

FROM scratch AS pages-source

COPY docs/ /
COPY web/tauth.js /tauth.js
COPY web/.nojekyll /.nojekyll

FROM scratch AS pages

COPY --from=pages-source / /
