# HTTP/2 Upstream Multiplexing

```text
request A -> ctx A -> stream A --+
request B -> ctx B -> stream B --+-> HTTP/2 session -> ngx_connection_t
request C -> ctx C -> stream C --+          |
|                                            +-> parse / validate inbound frame header
|                                            |   +-> connection frame
|                                            |   |   +-> process connection frames
|                                            |   |       +-> SETTINGS -> apply / ACK
|                                            |   |       +-> PING -> ACK
|                                            |   |       +-> GOAWAY -> drain session
|                                            |   |       +-> WINDOW_UPDATE (id = 0)
|                                            |   |           -> update connection window
|                                            |   +-> PUSH_PROMISE -> connection error
|                                            |   +-> stream frame
|                                            |       +-> stream map lookup
|                                            |       +-> dispatch request by stream id
|                                            |           with inbound stream frame
|                                            |
|                                            +-> handle session error
|                                            |   +-> send GOAWAY, if possible
|                                            |   +-> close connection
|                                            |   +-> notify active requests
|                                            |
|                                            +-> produce outbound connection frames
|                                            |   +-> SETTINGS / SETTINGS ACK
|                                            |   +-> PING ACK
|                                            |   +-> WINDOW_UPDATE (id = 0)
|                                            |   +-> GOAWAY
|                                            |
|                                            +-> write scheduler
|                                                +-> drain connection control queue
|                                                +-> select ready request stream
|                                                +-> enforce connection / stream DATA windows
|                                                +-> preserve HEADERS / CONTINUATION sequence
|                                                +-> write frames to connection
|                                                +-> retain partial writes / resume on write event
|
+-> process inbound stream frame
|   +-> HEADERS / CONTINUATION -> response headers
|   +-> DATA -> response body
|   +-> RST_STREAM -> finalize request
|   +-> WINDOW_UPDATE -> update send window
|   +-> PRIORITY -> ignore
|
+-> produce outbound stream frames
    +-> HEADERS / CONTINUATION -> request headers
    +-> DATA -> request body
    +-> RST_STREAM -> cancel request
    +-> WINDOW_UPDATE -> return receive credit
```

## Development Phases

The first three phases are behavior-preserving refactoring.  They keep one
active request per HTTP/2 session while establishing the ownership and event
boundaries needed by multiplexing.  Phase 4 enables multiple active streams and
includes the correctness and hardening work required by multiplexing.

## Phase 1: Sessionize the Connection

Move physical upstream connection ownership to the HTTP/2 session.  The session
owns the connection read event, input buffer, 9-byte frame header parser,
connection flow-control state, and connection-level frame processing.  It
handles SETTINGS, PING, GOAWAY, connection WINDOW_UPDATE, and connection
errors, while dispatching stream frames through a defined request boundary.

Keep one active request per session.  Request completion, retry, and sequential
keepalive reuse must not leave stale request references in the session.  The
phase is complete when existing single-stream proxy behavior is unchanged and
request code no longer owns connection-level input state.

## Phase 2: Streamize Requests

Introduce an explicit HTTP/2 stream object for each request and register it in
a session stream map.  The stream owns request-specific state, stream flow
control, request-owned events, and its inbound frame queue.  Give each request
a logical connection whose I/O callbacks are backed by the physical session
connection.

The session reads complete frames and dispatches them by stream ID.  A stream
frame must not retain references to the reusable session input buffer after
dispatch.  Attach and detach operations maintain session, stream, logical
connection, and request references as one lifecycle boundary.

Keep one active stream per session.  The phase is complete when all inbound
stream traffic passes through the stream registry and existing keepalive,
retry, cache, buffered, and unbuffered behaviors remain unchanged.

## Phase 3: Sessionize Writes

Move physical connection writes behind a session-owned write scheduler.  Keep
connection control output separate from stream output, preserve uninterrupted
HEADERS and CONTINUATION sequences, retain partial socket writes, and resume
the owning stream from the physical connection write event.

Represent socket-blocked, flow-control-blocked, and ready stream states
separately so that enabling multiple streams does not require another ownership
refactor.  Connection and stream DATA windows are enforced by the scheduler.

Keep one active stream per session.  The phase is complete when the session is
the sole owner of physical connection writes and existing single-stream output,
timeout, and retry behavior remains unchanged.

## Phase 4: Enable and Harden Multiplexing

Add a built-in per-worker HTTP/2 session pool, independent of upstream
keepalive and requiring no new configuration.  Reuse eligible active sessions,
attach multiple requests as streams, allocate stream IDs, and enforce peer
concurrency limits.

Complete the multiplexing behavior in the following areas:

- bound per-stream and per-session inbound queues, account receive windows when
  DATA is accepted, and return credit as buffered data is consumed;
- schedule ready streams fairly, allow other streams to progress while one is
  flow-control blocked, and preserve partial-write and header-block ownership;
- send RST_STREAM when a request is cancelled or times out, discard valid late
  frames for closed streams, and keep stream errors isolated from the session;
- drain sessions after GOAWAY, allow accepted streams to finish, and retry only
  streams the peer did not process when the request is safe to retry;
- define pool eligibility using the upstream transport and TLS identity, stop
  admitting streams before stream ID exhaustion, and close unusable sessions;
- cover concurrent and out-of-order responses, concurrency limits, flow
  control, cancellation, timeout, RST_STREAM, GOAWAY, connection errors,
  buffering, uploads, and TLS with automated tests.

The phase is complete when concurrent streams share one physical connection
without allowing a blocked, failed, or cancelled stream to corrupt, starve, or
unnecessarily terminate other streams, and the existing single-stream test
suite continues to pass.
