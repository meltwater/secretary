FROM golang:onbuild

WORKDIR /
VOLUME /keys

ADD launch.sh /
ENTRYPOINT ["/launch.sh"]
CMD ["daemon"]
