//! Every bound the relay enforces, in one place. Each is per account or per connection, so one account cannot
//! starve another (AGENTS.md: every buffer is bounded by a named constant).

use wmlhub_proto::v1;

/// The relay's bounds. [`Limits::default`] is a starting point, not a measured one.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest encoded `Frame` accepted or sent.
    pub max_frame_bytes: usize,
    /// Largest `Envelope.payload`.
    pub max_payload_bytes: usize,
    /// Longest principal id, account id and channel.
    pub max_id_bytes: usize,
    /// Longest `Envelope.coalesce`.
    pub max_coalesce_bytes: usize,

    /// Envelopes retained per session-events stream.
    pub ring_session_events: usize,
    /// Envelopes retained per telemetry stream.
    pub ring_telemetry: usize,
    /// Payload bytes retained across all of one account's rings; past it the largest ring gives up its oldest.
    pub account_ring_bytes: usize,
    /// Streams one account may have.
    pub max_streams_per_account: usize,

    /// Connections one account may have open.
    pub max_connections_per_account: usize,
    /// Accounts with state in this relay.
    pub max_accounts: usize,
    /// Streams one connection may subscribe to.
    pub max_subscriptions_per_connection: usize,

    /// Session-event envelopes queued for one connection before it is disconnected as a slow consumer.
    pub queue_session_events: usize,
    /// Telemetry envelopes queued for one connection before the oldest is dropped with a Gap.
    pub queue_telemetry: usize,
    /// Bytes queued for one connection, of every kind, before it is disconnected as a slow consumer.
    pub queue_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1 << 20,
            max_payload_bytes: (1 << 20) - 1024,
            max_id_bytes: 64,
            max_coalesce_bytes: 16,
            ring_session_events: 512,
            ring_telemetry: 256,
            account_ring_bytes: 64 << 20,
            max_streams_per_account: 1024,
            max_connections_per_account: 64,
            max_accounts: 10_000,
            max_subscriptions_per_connection: 256,
            queue_session_events: 1024,
            queue_telemetry: 128,
            queue_bytes: 16 << 20,
        }
    }
}

impl Limits {
    /// The part a peer is told in `Welcome`.
    pub fn announce(&self) -> v1::Limits {
        v1::Limits {
            max_frame_bytes: clamp_u32(self.max_frame_bytes),
            max_payload_bytes: clamp_u32(self.max_payload_bytes),
            ring_session_events: clamp_u32(self.ring_session_events),
            ring_telemetry: clamp_u32(self.ring_telemetry),
        }
    }
}

fn clamp_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}
