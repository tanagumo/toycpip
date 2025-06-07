use crate::ethernet::EthernetFrameError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetStackError {
    #[error("ethernet error: {0}")]
    Ethernet(#[from] EthernetFrameError),
}
