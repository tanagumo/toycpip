use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread;

use log::{debug, error, info, warn};
use thiserror::Error;

use crate::host::HOST_IP;
use crate::ip::{IpPacket, IpPacketError, Protocol};

use super::packet::{TcpPacket, WithSrcIp};

pub(crate) static TCP_LAYER: OnceLock<TcpLayer> = OnceLock::new();

#[derive(Debug, Error)]
pub(crate) enum SendError {
    #[error("failed to send packet")]
    SendError(#[from] mpsc::SendError<IpPacket>),
    #[error("failed to create ip packet: {0}")]
    PacketCreation(#[from] IpPacketError),
}

#[derive(Debug)]
pub(crate) struct TcpLayer {
    sender: Sender<WithSrcIp<TcpPacket>>,
    observers: Arc<Mutex<Vec<Sender<Arc<WithSrcIp<TcpPacket>>>>>>,
}

impl TcpLayer {
    pub(crate) fn start(
        ip_sender: impl Fn(WithSrcIp<TcpPacket>) -> Result<(), SendError> + Send + 'static,
        receiver: Receiver<Arc<IpPacket>>,
    ) -> Self {
        info!("Starting TCP layer");
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<WithSrcIp<TcpPacket>>>>::new()));
        let cloned_observers = Arc::clone(&observers);

        thread::Builder::new()
            .name("tcp_observe_tx".into())
            .spawn(move || {
                debug!("TCP receive thread started");
                loop {
                    if let Ok(ip_packet) = receiver.recv() {
                        debug!("Processing IP Packet for TCP packet extraction");

                        if ip_packet.protocol() != Protocol::TCP {
                            continue;
                        }

                        if ip_packet.dst_ip() != *HOST_IP.get().unwrap() {
                            continue;
                        }

                        let tcp_packet =
                            match TryInto::<WithSrcIp<TcpPacket>>::try_into(&*ip_packet) {
                                Ok(tcp_packet) => {
                                    debug!("TCP packet parsed successfully: {}", tcp_packet);
                                    tcp_packet
                                }
                                Err(e) => {
                                    warn!("Failed to parse TCP packet: {}", e);
                                    continue;
                                }
                            };
                        let tcp_packet = Arc::new(tcp_packet);
                        let mut guard = cloned_observers.lock().unwrap();
                        guard.retain(|sender| sender.send(Arc::clone(&tcp_packet)).is_ok());
                    }
                }
            })
            .unwrap();

        let (tx, rx) = mpsc::channel::<WithSrcIp<TcpPacket>>();
        thread::Builder::new()
            .name("tcp_send_tx".into())
            .spawn(move || {
                debug!("TCP send thread started");
                for tcp_packet in rx {
                    debug!("Sending TCP packet: {}", tcp_packet);
                    match ip_sender(tcp_packet) {
                        Ok(_) => {
                            debug!("TCP packet sent successfully");
                        }
                        Err(e) => {
                            error!("Failed to send TCP packet: {}", e);
                        }
                    }
                }
            })
            .unwrap();

        Self {
            sender: tx,
            observers,
        }
    }

    pub(crate) fn add_observer(&self, observer: Sender<Arc<WithSrcIp<TcpPacket>>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
        debug!("Added TCP observer: total_count={}", guard.len());
    }

    pub(crate) fn send(
        &self,
        packet: WithSrcIp<TcpPacket>,
    ) -> Result<(), mpsc::SendError<WithSrcIp<TcpPacket>>> {
        self.sender.send(packet)
    }
}
