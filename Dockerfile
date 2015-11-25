FROM golang:onbuild

WORKDIR /
VOLUME /keys

ENTRYPOINT ["app"]
CMD ["daemon"]
