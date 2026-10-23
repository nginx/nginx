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

## Architecture Guide

The diagram separates four lifetimes: request context, HTTP/2 stream, HTTP/2
session, and physical connection.

### Request Context

The request context owns proxy request and response processing.  It produces
outbound stream frames and consumes inbound stream frames.

### HTTP/2 Stream

A stream represents one request on a shared HTTP/2 connection.  It owns the
stream ID, stream flow-control state, inbound frame queue, and stream
connection.

### HTTP/2 Session

A session represents one HTTP/2 protocol connection.  It owns connection frame
parsing, connection flow control, the stream registry, connection errors, and
physical read and write scheduling.

### Physical Connection

The physical `ngx_connection_t` owns the socket, TLS state, and event-engine
registration.  Stream connections never register the shared socket directly.

### Inbound Flow

The session reads and validates one complete frame.  It processes connection
frames itself and routes stream frames through the stream registry to the target
request.

### Outbound Flow

Requests produce stream output, while the session produces connection output.
The session write scheduler serializes both kinds of output on the physical
connection.

### Lifecycle Boundary

A request and stream may finish while the session and physical connection remain
active.  Detaching a stream must remove every request reference without
disturbing sibling streams.

## Development Approach

We will build this architecture in four phases: sessionize the physical
connection, streamize requests, sessionize physical writes, and then enable and
harden multiplexing.  The first three phases preserve existing single-stream
behavior while establishing ownership boundaries; the fourth phase enables
multiple concurrent streams.  Detailed work items are listed below.

## Confirmed Design

### Stream Connection

A stream connection is a logical `ngx_connection_t` representing one HTTP/2
stream.  It adapts the existing upstream connection I/O and event interfaces to
the stream while the physical HTTP/2 connection is shared by multiple streams.

### Connection Input Buffer

The physical HTTP/2 connection owns the input buffer and frame-routing state.
They outlive individual stream connections, allowing in-flight frames for a
detached stream to be drained without retaining the request.

## Design Discussion

### HTTP/2 Session

#### Connection Frame Processing

SETTINGS, PING, GOAWAY, and WINDOW_UPDATE with stream ID 0 belong to the
physical HTTP/2 connection rather than to an individual request.

##### Request-Owned Processing

The connection demultiplexer passes a connection frame to the request that is
currently reading.  The request context parses the frame and applies its
effects.  Connection-level processing is therefore tied to the lifetime of an
arbitrarily selected request, even when a frame such as SETTINGS or GOAWAY
affects every stream.

##### Session-Owned Processing

The session read handler parses and processes connection frames before
dispatching stream frames.  Connection state and parser state remain independent
of request lifetime, and effects that apply to multiple streams are handled once
at connection scope.

#### Idle Connection Frame Handling

The backend can send connection frames after the last active stream detaches.

##### Close on Readable Data

The generic keepalive handler closes an idle connection whenever data becomes
readable.  This safely prevents reuse after GOAWAY, but also closes the
connection for valid PING or SETTINGS frames.

##### Protocol-Aware Idle Session

The session read handler remains active while the connection is idle.  It can
acknowledge PING, apply SETTINGS, and remove the connection from the pool when
GOAWAY is received.

The design question is whether an idle HTTP/2 connection should close on any
readable data or continue processing connection frames through the session.

#### Writes

##### Case 1: Header Block Interleaving

A header block can span multiple frames.  A HEADERS frame without `END_HEADERS`
must be followed by CONTINUATION frames for the same stream until `END_HEADERS`
is set.  If stream connections write independently without connection-level
serialization, the following sequence is possible:

```text
stream A: HEADERS       END_HEADERS=0
stream B: DATA
stream A: CONTINUATION  END_HEADERS=1
```

This is invalid because stream B interrupts stream A's header block.

##### Case 2: Cancellation During a Partial Write

Assume stream A is sending a DATA frame with a 100-byte payload.  The frame
header and the first 20 payload bytes are written before the socket blocks.
Stream A is then cancelled, leaving 80 payload bytes unsent.

```text
DATA header: length=100
DATA payload: 20 bytes sent, 80 bytes pending
stream A: cancelled
```

The peer still expects 80 bytes of DATA payload.  If RST_STREAM is sent
immediately, its bytes are parsed as part of that payload.  The remaining frame
cannot be dropped, while closing the shared physical connection would also
terminate unrelated streams.

###### Request-Owned Writer Design

```text
request A output path: 80 DATA bytes pending
conn_t output path:    RST_STREAM pending
```

The remaining DATA and RST_STREAM have different owners.  Cancellation detaches
request A, while the conn_t output path can send RST_STREAM independently.  The
design therefore does not preserve the required ordering across request
teardown.

###### Session-Owned Writer Design

The session writer owns both the partial DATA frame and RST_STREAM.
Cancellation stops stream A from producing new frames, but the session retains
the current frame.  It writes the remaining 80 bytes, discards later unsent
frames, sends RST_STREAM, and then detaches stream A.

#### Reads

##### Case 1: Stream Head-of-Line Blocking

Frames for different streams can arrive on the same physical connection:

```text
stream A: DATA
stream B: HEADERS  END_HEADERS=1
```

With proxy buffering enabled, downstream slowness is normally absorbed by
stream A's memory buffers and temporary file, so a slow client does not
immediately block other streams.  The buffering is still finite.  If stream A's
buffers fill and temporary-file buffering is disabled or reaches
`proxy_max_temp_file_size`, stream A stops reading.  If the shared reader cannot
buffer and dispatch past A's pending DATA, stream B cannot receive its HEADERS.

### Multiplexed Connection Pool

A multiplexed connection pool tracks HTTP/2 connections that can accept
additional streams while they are already in use.

#### Pool Key

The pool key determines whether two requests may share the same physical
connection.  Two requests can share a connection only when they select the same
backend and would create the connection in the same way:

```text
pool key = upstream block
         + backend IP address and port
         + HTTP or HTTPS
         + TLS name and certificate configuration
         + local bind address
```

If any of these values differ, the connection cannot be shared.  URI, request
headers, and response buffering belong to individual requests and are not part
of the key.  Connection health, GOAWAY state, and available stream capacity are
checked after a key match.

An extended keepalive pool obtains the upstream block from its keepalive
configuration.  A native HTTP/2 pool can obtain it from `u->upstream` and must
store it with the session.

#### Extended Upstream Keepalive Pool

The upstream keepalive module is extended to retain active multiplexed
connections.  The HTTP/2 layer reports whether a connection has spare stream
capacity, and keepalive makes the connection available to other requests.

#### Native HTTP/2 Session Pool

The HTTP/2 layer maintains a per-worker pool of active sessions independently
of upstream keepalive.  After peer selection, a request looks for a matching
session with spare stream capacity.

The design question is whether active connection sharing belongs to the generic
upstream keepalive module or to the HTTP/2 protocol layer.

#### User-Facing Behavior

Upstream HTTP/2 multiplexing is enabled automatically when
`proxy_http_version 2` is configured.  A request joins a matching connection
with spare stream capacity, or opens a new connection when none is available.

```nginx
upstream backend {
    server 127.0.0.1:8080;
}

location / {
    proxy_pass http://backend;
    proxy_http_version 2;
}
```

##### Maximum Concurrent Streams

The number of active streams on a connection must not exceed the backend's
`SETTINGS_MAX_CONCURRENT_STREAMS`.  A full connection continues serving its
existing streams but is not selected for new ones.  A new request uses another
matching connection or opens a new connection.

##### With an Extended Upstream Keepalive Pool

Multiplexing is available only when the upstream has a keepalive pool.  For an
explicit upstream, the default keepalive pool makes the basic configuration
above work without another directive.  `keepalive N` limits cache entries used
by both idle and active multiplexed connections, while disabling keepalive also
disables active connection sharing.  The current design shares only requests
with response buffering enabled.

##### With a Native HTTP/2 Session Pool

Active connection sharing does not depend on upstream keepalive configuration.
`proxy_http_version 2` is sufficient to use the native pool.  Upstream keepalive
controls whether a connection is retained after its last stream detaches, not
whether another request can join it while it is active.  Existing upstream
connection limits continue to control creation of new physical connections.

## Development Work Items

Each work item is one independently owned development unit.  Its owner analyzes,
implements, and tests that unit.

### All Phases

- **F01: Test Cases**
  Cover the complete HTTP/2 upstream multiplexing feature, including normal
  traffic, limits, cancellation, errors, TLS, and buffering modes.

### Phase 1: Sessionize the Connection

- **F02: Frame Parsing**
  Parse complete frame boundaries and validate frame headers before connection
  or stream processing begins.

- **F03: Frame Serialization**
  Build valid connection and stream frames without depending on request output
  chains or physical socket state.

- **F04: Session Lifecycle**
  Create and destroy connection-owned state without retaining references to a
  request after that request finishes.

- **F05: Session Read Handler**
  Read complete frames from the physical socket independently of any request's
  read event.

- **F06: Connection Frame Processing**
  Process SETTINGS, PING, GOAWAY, and connection WINDOW_UPDATE frames once at
  connection scope.

- **F07: Connection Flow Control**
  Track connection send and receive windows and process connection
  WINDOW_UPDATE frames.

### Phase 2: Streamize Requests

- **F08: Stream Connection**
  Represent one HTTP/2 stream through the connection and event interfaces used
  by the existing upstream code.

- **F09: Stream Registry**
  Register, find, and remove active streams by stream ID on one physical
  connection.

- **F10: Stream Frame Routing**
  Route each stream frame to the stream selected by its stream ID.

- **F11: Stream Input Queue**
  Preserve routed frames until the target stream is ready to consume them.

- **F12: Stream Flow Control**
  Track each stream's send and receive windows and process stream WINDOW_UPDATE
  frames.

- **F13: Stream Attach and Detach**
  Add and remove streams while cleaning timers, posted events, queues, and
  request references.

### Phase 3: Sessionize Writes

- **F14: Session Write Handler**
  Make one connection-level handler the only code that resumes writes to the
  physical socket.

- **F15: Stream Write Scheduling**
  Select ready streams fairly and allow other streams to progress when one is
  blocked.

- **F16: Partial Write Ownership**
  Retain the current stream and its unsent bytes until a partially written frame
  reaches a valid boundary.

- **F17: Header Block Ordering**
  Keep HEADERS and CONTINUATION frames uninterrupted until END_HEADERS.

- **F18: Connection Control Output**
  Queue and order SETTINGS ACK, PING ACK, connection WINDOW_UPDATE, and other
  connection-owned output with stream frames.

### Phase 4: Enable and Harden Multiplexing

- **F19: Per-Stream Rate Limiting**
  Preserve request rate limits without pausing the physical connection or
  slowing sibling streams.

- **F20: Maximum Concurrent Streams**
  Enforce SETTINGS_MAX_CONCURRENT_STREAMS when admitting a new stream to an
  existing connection.

- **F21: Multiplexed Connection Pool**
  Define the pool key, reuse sessions for the selected peer, track stream
  capacity, and move sessions between active and idle states.

- **F22: User Configuration**
  Enable multiplexing through proxy_http_version 2 and document connection pool
  and stream-capacity behavior.

- **F23: Queue and Memory Limits**
  Bound per-stream and per-session buffered data without blocking unrelated
  streams.

- **F24: TLS Upstream Support**
  Preserve TLS identity, handshake reuse, buffered writes, and error handling on
  shared upstream connections.

- **F25: Response Buffering Modes**
  Define and verify multiplexing behavior with proxy_buffering enabled and
  disabled.

- **F26: Idle Connection Frame Handling**
  Handle PING, SETTINGS, and GOAWAY after the last active stream detaches.

- **F27: Unprocessed Stream Retry**
  Retry requests rejected by REFUSED_STREAM or excluded by a GOAWAY last stream
  ID.

- **F28: Connection Errors**
  Mark a failed connection unusable and notify every attached stream.

- **F29: GOAWAY Draining**
  Stop admitting new streams while allowing streams accepted by the peer to
  finish.

- **F30: Connection Termination**
  Close the physical connection on transport, TLS, or connection protocol
  errors, idle expiry, worker shutdown, or after GOAWAY draining completes.

- **F31: Stream Termination**
  End one stream on END_STREAM, cancellation, timeout, RST_STREAM, or a stream
  error, while handling late frames and partial writes without harming siblings.

## First Production Target

Use [nginx issue #929](https://github.com/nginx/nginx/issues/929) as the first
production-readiness target.  An idle upstream HTTP/2 connection must consume
and process PING, SETTINGS, and GOAWAY instead of being closed merely because
data is readable.  Idle timeout and normal peer-close detection must continue to
work, and unread control-frame bytes must not cause an event loop.

Regression tests for this target must verify that an idle PING is acknowledged
and the connection is reused, idle SETTINGS are applied and acknowledged,
GOAWAY prevents reuse, idle timeout still closes the connection, and the same
behavior works over both cleartext and TLS upstream connections.
