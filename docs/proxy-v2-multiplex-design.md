## Phase 1 Goal

Establish a session-driven model for an H2 connection with one active request at a time. The session represents the H2 connection and drives physical I/O and protocol progress. Upstream supplies request output and consumes the corresponding stream's response results.

The current scope uses buffered responses and excludes proxy caching and `proxy_limit_rate`. Request-body buffering is separate: streaming request bodies and sequential keepalive reuse are already supported.

## Current Implementation

- The session owns frame parsing state, protocol control processing, and connection write progression. Streams retain decoded headers, body payload, and trailers for consumption.
- Physical reads are still driven by upstream's header path and event pipe. Proxy v2's header and body callbacks invoke the session parser; independent read progression is still a goal.
- Upstream has a request connection pointer, `u->connection`, which currently refers to `u->peer.connection`. Its `ignore_input` header path supports deferred results, but proxy v2 does not yet use it. A separate logical endpoint is not yet implemented.
- Session/stream attachment is lazy, stream storage uses the request pool, and the session write handler invokes the saved upstream handler. Physical connection establishment, TLS, and close/cache handling still use the upstream peer lifecycle.

## Required Properties

### Protocol Ownership and Progress

The session must be the sole driver of physical reads and writes. Protocol progress must be independent of response consumption, subject to transport availability, flow control, and bounded retention. Upstream consumes parsed results rather than transport frames.

Parsing must be request-independent and cover frame headers and payloads, fragmented input, padding, and skipping unknown frames where permitted by HTTP/2. Connection-level state belongs to the session; per-stream state and retained response results belong to the corresponding stream.

Completed protocol control results must take effect in wire order before processing subsequent frames. This includes `RST_STREAM`, SETTINGS initial-window changes, and stream and connection `WINDOW_UPDATE`. Processing may update state and schedule output or notifications without waiting for physical writes or response consumption.

### Response Results and Completion

Response results must remain available until consumed or explicitly abandoned. Headers and trailers retain their fields, block boundaries, and END_STREAM information. Body consumption must use parsed payload without further frame parsing.

No available result while a stream remains open means waiting. New results and terminal status must wake a waiting consumer, including trailers or completion with no new body bytes. Errors must be distinguishable from normal end. Normal end becomes observable only after preceding body payload and trailers have been delivered to the consumer.

### Bounded Retention and Flow Control

Retained body payload, header metadata, and pending output must be bounded. Metadata limits must account for accumulated retained results as well as individual header blocks.

Receiving body payload does not itself release its retained capacity. Capacity recovered through consumption or abandonment feeds back into receive-window management and the resumption of eligible work. Consumption may transfer payload into separately bounded upstream buffers; it need not wait for downstream transmission. Discarded padding can restore credit as it is skipped.

### Lifetimes, Cancellation, and Failures

Request/stream completion and resource release are distinct events. Resources must remain valid while parsing, queued output, notifications, or consumers still reference them, including borrowed request buffers and consumed header fields.

Cancellation may abandon retained results and must detach the consumer safely. Pending work must not access released request or stream storage. Retry must start with fresh per-attempt state. The session owns the decision to continue using or close its physical connection.

Stream failures and deadlines apply to the stream; connection failures affect the streams using that connection. Failure and timeout handling must preserve these scopes.

## Completion Criteria

Phase 1 is complete when a request can be attached, sent, and its response headers, buffered body, trailers, and normal end or error consumed while the session drives physical I/O and protocol progress. Completion, cancellation, and retry must preserve resource lifetimes and leave the connection in a valid reusable or closed state.

Operation must resume after flow-control or consumer-backpressure stalls. In particular, a paused response consumer must not prevent the session from processing available control frames within the retention limits and resuming eligible output.

## Verification

- For implementation changes, build the revision being tested and run the proxy v2 suite before and after the change to establish a baseline and detect regressions. Changes to shared upstream paths also require relevant regression coverage for their other callers.
- Use `/tmp/nginx-tests` and run the test harness, nginx, and backend daemons as a non-root user. Set `TEST_NGINX_BINARY` to the absolute path of the binary being tested. From `/tmp/nginx-tests`, run:

  ```sh
  TEST_NGINX_BINARY=/absolute/path/to/nginx prove -v proxy_h2*.t
  ```

- Add focused tests for changed behavior and ownership boundaries. As applicable, cover fragmented input, padding, malformed frames, deferred consumption, bounded retention, flow-control recovery, cancellation, retry, and completion ordering.
- For changes to buffer ownership or resource lifetimes, also verify with a sanitizer build. Inspect test and nginx logs; investigate crashes, memory leaks, and sanitizer warnings before considering verification complete.
- Record the build and test commands, results, and any skipped tests or unresolved failures with the change so reviewers can reproduce the verification.
