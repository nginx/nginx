etag 304 error


ETAG does not provide a customizable generation method. The same etag generated using both br and etag may result in exceptions for both br and gzip clients.



curl -vob  'https://xxx.abc.com/chunk-a96413db6698ff5dcd9a.js' -H "Accept-Encoding:gzip, deflate, br"
< content-encoding: br
< etag: W/"65afb858-197d8b"

curl -vob  'https://xxx.abc.com/chunk-a96413db6698ff5dcd9a.js' -H "Accept-Encoding:gzip"
< content-encoding: gzip
< etag: W/"65afb858-197d8b"

curl -vob  'https://xxx.abc.com/chunk-a96413db6698ff5dcd9a.js' -H "Accept-Encoding:br"
< content-encoding: br
< etag: W/"65afb858-197d8b"

curl -vob  'https://xxx.abc.com/chunk-a96413db6698ff5dcd9a.js'
< no content-encoding
< etag: "65afb858-197d8b"
