//! The box connector: reads one box's `/api/events` and republishes every frame through a hub, sealed
//! (docs/design/box-connector.md).
//!
//! What it does not do is as much the point as what it does: it never decodes a frame. It reads two tags to decide
//! which channel a frame belongs on (`wmlhub-box`), seals the bytes as they came, and publishes them. A client
//! decodes what the box wrote, not what a connector re-encoded.

pub mod events;
pub mod grant;
pub mod http;
pub mod pair;
pub mod relay;
pub mod revoked;
pub mod run;
pub mod serve;
pub mod state;

pub use events::{Events, IngestError};
pub use http::Target;
pub use pair::{Left, Offer, PairError};
pub use relay::{Channels, Relay, Relayed};
pub use run::{Connector, ConnectorError, Pass};
pub use serve::{ServeError, Served, Serving};
pub use state::State;
