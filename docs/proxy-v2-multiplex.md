# Proxy v2 multiplex design

This document describes how to change the HTTP/2 proxy implementation from
request-driven processing to connection-driven processing.  The first phase
still uses one upstream connection for one active HTTP/2 stream.  Multiplexing
can be added after ownership of the connection has moved to a session.

## Model

The implementation uses three objects:

1. A real connection owns the upstream socket and performs network I/O.
2. A session owns the real connection and HTTP/2 connection state.
3. A stream has a fake connection that presents stream data to the existing
   upstream code.

The receive path is:

```text
upstream socket
    -> real connection
    -> session buffer and frame dispatcher
    -> fake stream connection
    -> upstream header parser or event pipe
```

The send path is:

```text
upstream request or session control frame
    -> session output queue
    -> real connection
    -> upstream socket
```

## Phase 1 constraints

Keep the first phase deliberately small:

1. Use one upstream connection for one active stream.
2. Use only the buffered response path.
3. Buffer the request body before sending it upstream.
4. Do not support cache or `proxy_limit_rate`.
5. Preserve the existing stream header, body, and trailer parsers where
   practical.

## Implementation order

Each step should be a separate, buildable commit with its existing tests
passing.

### 1. Reduce the supported paths

Remove the cache and non-buffered request and response paths from the HTTP/2
proxy module.  Always use the buffered event-pipe path and prevent response
headers such as `X-Accel-Buffering` from switching it back to non-buffered
processing.  Disable the event-pipe rate limit for this path.

This gives the connection-driven implementation a single upstream read model.

### 2. Introduce the session

Add a session object for state whose lifetime and scope belong to the real
upstream connection.  Initially link it to the existing request context
without changing I/O behavior.

The session will eventually own:

- the real upstream connection;
- the connection receive buffer;
- connection flow-control windows;
- the last allocated stream identifier;
- frame-header parsing state;
- connection-level frame state and output queues.

Allocate the session from the real connection pool so that it survives while
the connection is in the upstream keepalive cache.

### 3. Introduce the stream

Add a stream object for request-scoped HTTP/2 state and link it to both the
request and its session.  Move the following state into it:

- the stream identifier;
- stream flow-control windows;
- header parsing state;
- stream completion state.

Only one stream is attached to a session in this phase.  Keep the attachment
explicit so that a later phase can replace it with a stream lookup structure.

### 4. Move frame parsing into the session

Move the frame-header parser and its state into the session.  Both the header
and body paths should call one session function to parse and validate frame
headers.

Do not change socket ownership or event handling in this step.  The request
continues to drive reads, making this a mechanical state-ownership change.

### 5. Move connection frame processing into the session

Make the session consume connection-level frames after parsing their headers:

- apply SETTINGS and queue SETTINGS acknowledgements;
- apply connection and stream WINDOW_UPDATE frames;
- reply to PING frames;
- record GOAWAY and prevent connection reuse;
- reject PUSH_PROMISE and invalid frame sequences;
- skip unknown connection-level frames.

Stream-level HEADERS, DATA, CONTINUATION, and RST_STREAM frames remain for the
stream parser.  Socket reads are still request-driven in this step.

### 6. Make the session drive connection writes

Move connection-level output into a session-owned queue and make the session
responsible for scheduling writes on the real connection.

The write path must:

- preserve frame ordering between request and connection-level frames;
- support partial writes and `NGX_AGAIN`;
- keep socket and TLS state on the real connection;
- wake a stream when a SETTINGS or WINDOW_UPDATE change removes a flow-control
  block;
- handle write timeout and connection errors independently of stream parsing.

At the end of this step, connection-level frames must no longer depend on a
request output filter invocation merely to be sent.

### 7. Introduce the fake stream connection

Create the fake connection only after the TCP connection and, when used, the
TLS handshake have completed.  At that point:

1. Save the real connection in the session.
2. Create request-owned fake read and write events.
3. Keep all socket writes bound to the real connection.
4. Present the fake connection as the request's upstream connection.
5. Install session handlers on the real connection.

The fake connection must not own or close the socket, and its events must not
be registered with the operating-system event backend.

### 8. Make the session drive connection reads

The real connection's read handler performs the following operations in order:

1. Read available bytes from the upstream socket into the session buffer.
2. Parse frame headers from that buffer.
3. Consume complete connection-level frames.
4. Stop when a frame for the active stream is available.
5. Mark the fake connection readable and post its read event.

The session must not parse beyond an unconsumed stream frame.  This preserves
frame order and prevents connection-level data from leaking into the stream.

### 9. Read stream data through the fake connection

Implement the fake connection's `recv` and `recv_chain` methods by copying data
from the session buffer.  They never read the real socket.

Both methods must:

- return only bytes belonging to the active stream frame;
- preserve normal nginx return values: a byte count, `NGX_AGAIN`, zero for
  EOF, or `NGX_ERROR`;
- respect the `recv_chain` limit without advancing destination buffer
  pointers, since the event pipe advances them itself;
- clear fake read readiness when no stream bytes remain;
- resume the session reader after the stream consumes a frame.

If the existing stream parser still expects to parse a frame header, the
session may replay the already parsed header through the fake connection as a
transition step.  Validation and flow-control accounting must happen only
once.

### 10. Restore the real connection before release

Before retrying, finalizing, or returning a connection to the keepalive cache:

1. Remove fake events from posted and timer queues.
2. Restore the real connection's event handlers.
3. Restore the real connection as the peer and event-pipe connection.
4. Detach the stream from the session.
5. Call the original peer release callback with the real connection.

This ordering is required because a fake connection must never be closed by
the upstream core or stored in the keepalive cache.  All retry and error paths
must use the same restoration logic as normal finalization.

### 11. Reuse an idle session

When a real connection is obtained from the keepalive cache, recover its
session from the connection pool, attach a new stream, assign the next stream
identifier, and create a new request-owned fake connection.

A session is reusable only when:

- the stream has completed;
- no stream frame or payload remains buffered;
- no connection-level output frame remains queued;
- the frame parser is between frames;
- the request output is complete;
- no GOAWAY, EOF, protocol error, or socket error has occurred.

## Required validation

Each implementation step should build with warnings treated as errors.  Before
completing the connection-driven phase, run all `proxy_h2*.t` tests as a
non-root user.

Additional tests should cover:

- partial frame headers and payloads;
- connection frames adjacent to stream frames;
- partial writes of session frames;
- upstream EOF, read timeout, and write timeout;
- retry before and after response headers;
- keepalive reuse;
- cleanup of posted fake events.
