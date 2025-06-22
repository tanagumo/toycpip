use std::fmt::Display;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum TcpState {
    CloseWait,
    Closed,
    Closing,
    Established,
    FinWait1,
    FinWait2,
    LastAck,
    Listen,
    SynReceived,
    SynSent,
    TimeWait,
}

impl TcpState {
    pub(crate) fn can_transit_to(&self, next_state: Self) -> bool {
        use TcpState as TS;
        match self {
            TS::CloseWait => next_state == TS::LastAck,
            TS::Closed => next_state == TS::SynSent || next_state == TS::Listen,
            TS::Closing => next_state == TS::TimeWait,
            TS::Established => next_state == TS::FinWait1 || next_state == TS::CloseWait,
            TS::FinWait1 => next_state == TS::FinWait2 || next_state == TS::Closing,
            TS::FinWait2 => next_state == TS::TimeWait,
            TS::LastAck => next_state == TS::Closed,
            TS::Listen => {
                next_state == TS::SynReceived
                    || next_state == TS::SynSent
                    || next_state == TS::Closed
            }
            TS::SynReceived => next_state == TS::Established || next_state == TS::FinWait1,
            TS::SynSent => {
                next_state == TS::Closed
                    || next_state == TS::SynReceived
                    || next_state == TS::Established
            }
            TS::TimeWait => next_state == TS::Closed,
        }
    }
}

impl Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            TcpState::CloseWait => "CLOSE-WAIT",
            TcpState::Closed => "CLOSED",
            TcpState::Closing => "CLOSING",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN-WAIT-1",
            TcpState::FinWait2 => "FIN-WAIT-2",
            TcpState::LastAck => "LAST-ACK",
            TcpState::Listen => "LISTEN",
            TcpState::SynReceived => "SYN-RECEIVED",
            TcpState::SynSent => "SYN-SENT",
            TcpState::TimeWait => "TIME-WAIT",
        };

        write!(f, "{}", value)
    }
}
