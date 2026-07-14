//! Relay v2 在线 `Send` / `Reply` 的无状态目标解析。

use std::fmt;

use agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_FORBIDDEN;
use agentdeck_protocol::relay_v2::frame::{AcceptedRef, Reply, RouteAccepted, Send};
use agentdeck_protocol::relay_v2::{RelayFailure, RequestRouteId};

use crate::v2::auth::{AccessContext, PrincipalRoute};

/// 一次在线 request 的 actor-local 路由结果；不创建 seen/origin/TTL map。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestTarget {
    principal: PrincipalRoute,
    request_route: RequestRouteId,
}

impl RequestTarget {
    pub(crate) fn principal(self) -> PrincipalRoute {
        self.principal
    }

    pub(crate) fn accepted(self) -> RouteAccepted {
        request_accepted(self.request_route)
    }
}

impl fmt::Debug for RequestTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestTarget")
            .field("principal", &self.principal)
            .field("request", &self.request_route.redacted())
            .finish()
    }
}

/// Device 只能以自身 device route 发送，并且目标固定为其所属 machine trust domain。
pub(crate) fn resolve_send(
    access: &AccessContext,
    frame: &Send,
) -> Result<RequestTarget, RelayFailure> {
    let Some(PrincipalRoute::Device {
        machine_route,
        device_route,
    }) = access.principal_route()
    else {
        return Err(forbidden());
    };
    if device_route != frame.device_route {
        return Err(forbidden());
    }
    Ok(RequestTarget {
        principal: PrincipalRoute::Machine(machine_route),
        request_route: frame.request_route,
    })
}

/// Machine Reply 的 device target 永远带上 origin machine route，不能猜到其他 trust domain。
pub(crate) fn resolve_reply(
    access: &AccessContext,
    frame: &Reply,
) -> Result<RequestTarget, RelayFailure> {
    let Some(PrincipalRoute::Machine(machine_route)) = access.principal_route() else {
        return Err(forbidden());
    };
    Ok(RequestTarget {
        principal: PrincipalRoute::Device {
            machine_route,
            device_route: frame.device_route,
        },
        request_route: frame.request_route,
    })
}

/// `requestRoute` 只原样关联本次有界 writer admission，不承担 origin 恢复或去重。
pub(crate) fn request_accepted(request_route: RequestRouteId) -> RouteAccepted {
    RouteAccepted {
        accepted: AcceptedRef::Request { request_route },
    }
}

fn forbidden() -> RelayFailure {
    RelayFailure::new(
        RELAY_ROUTE_FORBIDDEN,
        "frame is not allowed for this access",
    )
}

#[cfg(test)]
mod tests {
    use agentdeck_protocol::relay_v2::failure::RELAY_ROUTE_FORBIDDEN;
    use agentdeck_protocol::relay_v2::frame::{
        AcceptedRef, Reply, RouteAccepted, SealedBlob, Send,
    };
    use agentdeck_protocol::relay_v2::{
        ConnectionInstanceId, DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId,
        PairRouteId, RelayServerId, RequestRouteId, TrustEpoch,
    };

    use crate::v2::auth::{
        AccessContext, DeviceAccess, MachineAccess, PairingAccess, PrincipalRoute,
    };

    use super::*;

    fn machine(seed: u8) -> MachineRouteId {
        MachineRouteId::from_bytes([seed; 16])
    }

    fn device(seed: u8) -> DeviceRouteId {
        DeviceRouteId::from_bytes([seed; 16])
    }

    fn request(seed: u8) -> RequestRouteId {
        RequestRouteId::from_bytes([seed; 16])
    }

    fn connection(seed: u8) -> ConnectionInstanceId {
        ConnectionInstanceId::from_bytes([seed; 16])
    }

    fn machine_access(machine_route: MachineRouteId) -> AccessContext {
        AccessContext::Machine(MachineAccess {
            machine_route,
            connection_instance: connection(0x31),
            trust_epoch: TrustEpoch::new(3),
            link_generation: LinkGeneration::new(5),
            cert_hash: [0x41; 32],
            absolute_expiry_ms: None,
        })
    }

    fn device_access(machine_route: MachineRouteId, device_route: DeviceRouteId) -> AccessContext {
        AccessContext::Device(DeviceAccess {
            machine_route,
            device_route,
            connection_instance: connection(0x32),
            grant_serial: GrantSerial::new(7),
            grant_hash: [0x42; 32],
            device_sign_fingerprint: [0x43; 32],
        })
    }

    fn pairing_access(machine_route: MachineRouteId) -> AccessContext {
        AccessContext::Pairing(PairingAccess {
            relay_server_id: RelayServerId::from_bytes([0x44; 16]),
            machine_route,
            pair_route: PairRouteId::from_bytes([0x45; 16]),
            connection_instance: connection(0x33),
            absolute_expiry_ms: 10_000,
        })
    }

    fn send(device_route: DeviceRouteId, request_route: RequestRouteId) -> Send {
        Send {
            device_route,
            request_route,
            sealed_blob: SealedBlob(vec![0xa1, 0xa2]),
        }
    }

    fn reply(device_route: DeviceRouteId, request_route: RequestRouteId) -> Reply {
        Reply {
            device_route,
            request_route,
            sealed_blob: SealedBlob(vec![0xb1, 0xb2]),
        }
    }

    #[test]
    fn device_send_requires_its_exact_self_route_and_targets_own_machine() {
        let machine_route = machine(0x11);
        let device_route = device(0x21);
        let request_route = request(0x51);
        let access = device_access(machine_route, device_route);

        let target = resolve_send(&access, &send(device_route, request_route))
            .expect("self-routed device Send");

        assert_eq!(target.principal(), PrincipalRoute::Machine(machine_route));
        assert_eq!(
            target.accepted(),
            request_accepted(request_route),
            "requestRoute is an opaque ACK correlation ID"
        );
    }

    #[test]
    fn device_send_cannot_claim_another_device_route() {
        let access = device_access(machine(0x12), device(0x22));
        let error = resolve_send(&access, &send(device(0x23), request(0x52)))
            .expect_err("self-route mismatch must be rejected before target lookup");

        assert_eq!(error.code, RELAY_ROUTE_FORBIDDEN);
        assert_eq!(error.in_reply_to, None);
    }

    #[test]
    fn only_device_access_can_send() {
        let machine_route = machine(0x13);
        let frame = send(device(0x24), request(0x53));

        for access in [machine_access(machine_route), pairing_access(machine_route)] {
            assert_eq!(
                resolve_send(&access, &frame)
                    .expect_err("non-device Send must be rejected")
                    .code,
                RELAY_ROUTE_FORBIDDEN
            );
        }
    }

    #[test]
    fn machine_reply_targets_device_inside_its_own_trust_domain() {
        let machine_route = machine(0x14);
        let device_route = device(0x25);
        let request_route = request(0x54);

        let target = resolve_reply(
            &machine_access(machine_route),
            &reply(device_route, request_route),
        )
        .expect("machine Reply");

        assert_eq!(
            target.principal(),
            PrincipalRoute::Device {
                machine_route,
                device_route,
            },
            "the frame cannot select a foreign machine trust domain"
        );
        assert_eq!(
            target.accepted(),
            RouteAccepted {
                accepted: AcceptedRef::Request { request_route },
            }
        );
    }

    #[test]
    fn only_machine_access_can_reply() {
        let machine_route = machine(0x15);
        let device_route = device(0x26);
        let frame = reply(device_route, request(0x55));

        for access in [
            device_access(machine_route, device_route),
            pairing_access(machine_route),
        ] {
            assert_eq!(
                resolve_reply(&access, &frame)
                    .expect_err("non-machine Reply must be rejected")
                    .code,
                RELAY_ROUTE_FORBIDDEN
            );
        }
    }

    #[test]
    fn request_route_is_not_a_seen_map_or_origin_lookup_key() {
        let machine_route = machine(0x16);
        let device_route = device(0x27);
        let request_route = request(0x56);
        let access = device_access(machine_route, device_route);
        let frame = send(device_route, request_route);

        let first = resolve_send(&access, &frame).expect("first stateless resolution");
        let retry = resolve_send(&access, &frame).expect("same opaque ID resolves again");

        assert_eq!(first, retry);
        assert_eq!(first.accepted(), request_accepted(request_route));
    }

    #[test]
    fn request_target_debug_redacts_every_route() {
        let machine_route = machine(0xa7);
        let device_route = device(0xb8);
        let request_route = request(0xc9);
        let target = resolve_reply(
            &machine_access(machine_route),
            &reply(device_route, request_route),
        )
        .expect("machine Reply target");

        let rendered = format!("{target:?}");
        for raw in [
            format!("{machine_route:?}"),
            format!("{device_route:?}"),
            format!("{request_route:?}"),
        ] {
            assert!(!rendered.contains(&raw), "Debug leaked raw route: {raw}");
        }
        assert!(rendered.contains(&machine_route.redacted()));
        assert!(rendered.contains(&device_route.redacted()));
        assert!(rendered.contains(&request_route.redacted()));
        assert!(!rendered.contains("sealed_blob"));
    }
}
