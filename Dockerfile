FROM golang:1.7

ADD . /go/src/github.com/jmhodges/secupdate_bug
RUN go install github.com/jmhodges/secupdate_bug

CMD secupdate_bug
