Examples Docker image
---------------------
You can experiment with [http3-client](http3-client.rs),
[http3-server](http3-server.rs), [client](client.rs) and [server](server.rs)
using Docker.

The Examples [Dockerfile](Dockerfile) builds a Debian image.

To build:

```
docker build -t quiceh .
```

To make an HTTP/3 request:

```
docker run -it quiceh http3-client https://reverso.info.unamur.be
```
