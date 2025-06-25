pub(crate) mod connection;
pub(crate) mod layer;
pub(crate) mod packet;

use std::sync::{Arc, mpsc::Receiver};

pub(crate) use layer::{SendError, TCP_LAYER, TcpLayer};
pub(crate) use packet::{TcpPacket, WithPeerIp};

use crate::ip::IpPacket;

pub(crate) fn setup(
    ip_sender: impl Fn(WithPeerIp<TcpPacket>) -> Result<(), SendError> + Send + 'static,
    receiver: Receiver<Arc<IpPacket>>,
) -> &'static TcpLayer {
    TCP_LAYER.get_or_init(|| TcpLayer::start(ip_sender, receiver))
}
