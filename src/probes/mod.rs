//! Active protocol probes used after a host has already been discovered.
//!
//! These modules intentionally live below `probes` rather than at crate root:
//! they all perform network I/O against known hosts and produce identity
//! evidence. Discovery modules answer "is there a host?", while probe modules
//! answer "what does this host look like?".

pub mod deep;
pub mod smb;
pub mod snmp;
pub mod upnp;
