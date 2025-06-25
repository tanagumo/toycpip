use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use log::{debug, error, info, warn};
use thiserror::Error;

use crate::host::HOST_IP;
use crate::ip::{IpPacket, IpPacketError, Protocol};

use super::packet::{TcpPacket, WithPeerIp};

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
    sender: Sender<WithPeerIp<TcpPacket>>,
    observers: Arc<Mutex<Vec<Sender<Arc<WithPeerIp<TcpPacket>>>>>>,
    running: Arc<AtomicBool>,
    observe_thread_handle: Option<JoinHandle<()>>,
    send_thread_handle: Option<JoinHandle<()>>,
}

impl Drop for TcpLayer {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);

        if let Some(observe_thread_handle) = self.observe_thread_handle.take() {
            observe_thread_handle.join().unwrap();
        }
        if let Some(send_thread_handle) = self.send_thread_handle.take() {
            send_thread_handle.join().unwrap();
        }
    }
}

impl TcpLayer {
    pub(crate) fn start(
        ip_sender: impl Fn(WithPeerIp<TcpPacket>) -> Result<(), SendError> + Send + 'static,
        receiver: Receiver<Arc<IpPacket>>,
    ) -> Self {
        info!("Starting TCP layer");
        let observers = Arc::new(Mutex::new(Vec::<Sender<Arc<WithPeerIp<TcpPacket>>>>::new()));
        let cloned_observers = Arc::clone(&observers);
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);

        let observe_thread_handle = thread::Builder::new()
            .name("tcp_observe_tx".into())
            .spawn(move || {
                debug!("TCP receive thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(ip_packet) = receiver.recv_timeout(Duration::from_millis(100)) {
                        debug!("Processing IP Packet for TCP packet extraction");

                        if ip_packet.protocol() != Protocol::TCP {
                            continue;
                        }

                        if ip_packet.dst_ip() != *HOST_IP.get().unwrap() {
                            continue;
                        }

                        let tcp_packet =
                            match TryInto::<WithPeerIp<TcpPacket>>::try_into(&*ip_packet) {
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

        let (tx, rx) = mpsc::channel::<WithPeerIp<TcpPacket>>();
        let r = Arc::clone(&running);
        let send_thread_handle = thread::Builder::new()
            .name("tcp_send_tx".into())
            .spawn(move || {
                debug!("TCP send thread started");

                while r.load(Ordering::Relaxed) {
                    if let Ok(tcp_packet) = rx.recv_timeout(Duration::from_millis(100)) {
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
                }
            })
            .unwrap();

        Self {
            sender: tx,
            observers,
            running,
            observe_thread_handle: Some(observe_thread_handle),
            send_thread_handle: Some(send_thread_handle),
        }
    }

    pub(crate) fn add_observer(&self, observer: Sender<Arc<WithPeerIp<TcpPacket>>>) {
        let mut guard = self.observers.lock().unwrap();
        guard.push(observer);
        debug!("Added TCP observer: total_count={}", guard.len());
    }

    pub(crate) fn send(
        &self,
        packet: WithPeerIp<TcpPacket>,
    ) -> Result<(), mpsc::SendError<WithPeerIp<TcpPacket>>> {
        self.sender.send(packet)
    }
}
