//! 已验证 Relay v2 principal、active generation CAS 与受限 PairingAccess。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use agentdeck_protocol::relay_v2::failure::{
    RELAY_AUTH_INVALID_GRANT, RELAY_QUOTA_EXCEEDED, RELAY_ROUTE_FORBIDDEN, RELAY_ROUTE_NOT_FOUND,
    RELAY_STORE_UNAVAILABLE, RELAY_VERSION_UNSUPPORTED,
};
use agentdeck_protocol::relay_v2::frame::{ClosePairRoute, PairData};
use agentdeck_protocol::relay_v2::{
    ConnectionInstanceId, DeviceRouteId, GrantSerial, LinkGeneration, MachineRouteId,
    OpaqueRouteFrame, PairRouteId, RELAY_PROTOCOL_VERSION, RelayFailure, RelayFrameBody,
    RelayServerId, TrustEpoch,
};

#[derive(Clone, PartialEq, Eq)]
pub struct MachineAccess {
    pub(crate) machine_route: MachineRouteId,
    pub(crate) connection_instance: ConnectionInstanceId,
    pub(crate) trust_epoch: TrustEpoch,
    pub(crate) link_generation: LinkGeneration,
    pub(crate) cert_hash: [u8; 32],
}

impl fmt::Debug for MachineAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MachineAccess")
            .field("machine", &self.machine_route.redacted())
            .field("generation", &self.link_generation.value())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceAccess {
    pub(crate) machine_route: MachineRouteId,
    pub(crate) device_route: DeviceRouteId,
    pub(crate) connection_instance: ConnectionInstanceId,
    pub(crate) grant_serial: GrantSerial,
    pub(crate) grant_hash: [u8; 32],
    pub(crate) device_sign_fingerprint: [u8; 32],
}

impl fmt::Debug for DeviceAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAccess")
            .field("machine", &self.machine_route.redacted())
            .field("device", &self.device_route.redacted())
            .field("serial", &self.grant_serial.value())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PairingAccess {
    pub(crate) relay_server_id: RelayServerId,
    pub(crate) machine_route: MachineRouteId,
    pub(crate) pair_route: PairRouteId,
    pub(crate) connection_instance: ConnectionInstanceId,
    pub(crate) absolute_expiry_ms: u64,
}

impl fmt::Debug for PairingAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingAccess")
            .field("machine", &self.machine_route.redacted())
            .field("pair", &self.pair_route.redacted())
            .field("absolute_expiry_ms", &self.absolute_expiry_ms)
            .finish_non_exhaustive()
    }
}

impl PairingAccess {
    /// Pairing connection 的唯一数据面能力：同 route 的 PairData / ClosePairRoute。
    /// 每一帧都重新检查 absolute expiry，不能只在连接建立时检查一次。
    pub fn authorize_frame(
        &self,
        frame: &OpaqueRouteFrame,
        now_ms: u64,
    ) -> Result<(), RelayFailure> {
        if now_ms >= self.absolute_expiry_ms {
            return Err(failure(
                RELAY_ROUTE_NOT_FOUND,
                "pair route is unavailable or expired",
            ));
        }
        if frame.version != RELAY_PROTOCOL_VERSION {
            return Err(failure(
                RELAY_VERSION_UNSUPPORTED,
                "unsupported Relay protocol version",
            ));
        }
        match &frame.body {
            RelayFrameBody::PairData(PairData { pair_route, .. })
                if *pair_route == self.pair_route =>
            {
                Ok(())
            }
            RelayFrameBody::ClosePairRoute(ClosePairRoute {
                machine_route,
                pair_route,
            }) if *machine_route == self.machine_route && *pair_route == self.pair_route => Ok(()),
            _ => Err(failure(
                RELAY_ROUTE_FORBIDDEN,
                "frame is not allowed for pairing access",
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum AccessContext {
    Machine(MachineAccess),
    Device(DeviceAccess),
    Pairing(PairingAccess),
}

impl fmt::Debug for AccessContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine(access) => access.fmt(formatter),
            Self::Device(access) => access.fmt(formatter),
            Self::Pairing(access) => access.fmt(formatter),
        }
    }
}

impl AccessContext {
    pub fn connection_instance(&self) -> ConnectionInstanceId {
        match self {
            Self::Machine(access) => access.connection_instance,
            Self::Device(access) => access.connection_instance,
            Self::Pairing(access) => access.connection_instance,
        }
    }

    pub fn principal_route(&self) -> Option<PrincipalRoute> {
        match self {
            Self::Machine(access) => Some(PrincipalRoute::Machine(access.machine_route)),
            Self::Device(access) => Some(PrincipalRoute::Device {
                machine_route: access.machine_route,
                device_route: access.device_route,
            }),
            Self::Pairing(_) => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairingHello {
    pub protocol_version: u16,
    pub relay_server_id: RelayServerId,
    pub connection_instance: ConnectionInstanceId,
    pub pair_route: PairRouteId,
}

impl fmt::Debug for PairingHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingHello")
            .field("protocol_version", &self.protocol_version)
            .field("pair", &self.pair_route.redacted())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActivePairRoute {
    pub relay_server_id: RelayServerId,
    pub machine_route: MachineRouteId,
    pub pair_route: PairRouteId,
    pub absolute_expiry_ms: u64,
}

impl fmt::Debug for ActivePairRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivePairRoute")
            .field("machine", &self.machine_route.redacted())
            .field("pair", &self.pair_route.redacted())
            .field("absolute_expiry_ms", &self.absolute_expiry_ms)
            .finish_non_exhaustive()
    }
}

/// P2.4 PairRoute registry 交给 auth 的单 route 只读快照；不在 P2.2 持久化 route。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PairRouteView {
    pub now_ms: u64,
    pub active_route: Option<ActivePairRoute>,
}

impl fmt::Debug for PairRouteView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairRouteView")
            .field("now_ms", &self.now_ms)
            .field("has_active_route", &self.active_route.is_some())
            .finish()
    }
}

pub fn authorize_pairing_route(
    hello: PairingHello,
    routes: &PairRouteView,
) -> Result<PairingAccess, RelayFailure> {
    if hello.protocol_version != RELAY_PROTOCOL_VERSION {
        return Err(failure(
            RELAY_VERSION_UNSUPPORTED,
            "unsupported Relay protocol version",
        ));
    }
    let route = routes.active_route.ok_or_else(|| {
        failure(
            RELAY_ROUTE_NOT_FOUND,
            "pair route is unavailable or expired",
        )
    })?;
    if route.relay_server_id != hello.relay_server_id || route.pair_route != hello.pair_route {
        return Err(failure(
            RELAY_ROUTE_NOT_FOUND,
            "pair route is unavailable or expired",
        ));
    }
    if routes.now_ms >= route.absolute_expiry_ms {
        return Err(failure(
            RELAY_ROUTE_NOT_FOUND,
            "pair route is unavailable or expired",
        ));
    }
    Ok(PairingAccess {
        relay_server_id: route.relay_server_id,
        machine_route: route.machine_route,
        pair_route: route.pair_route,
        connection_instance: hello.connection_instance,
        absolute_expiry_ms: route.absolute_expiry_ms,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrincipalRoute {
    Machine(MachineRouteId),
    Device {
        machine_route: MachineRouteId,
        device_route: DeviceRouteId,
    },
}

impl fmt::Debug for PrincipalRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine(machine) => formatter
                .debug_tuple("Machine")
                .field(&machine.redacted())
                .finish(),
            Self::Device {
                machine_route,
                device_route,
            } => formatter
                .debug_struct("Device")
                .field("machine", &machine_route.redacted())
                .field("device", &device_route.redacted())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ActiveEntry {
    connection_instance: ConnectionInstanceId,
    authority: u64,
    credential_hash: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActiveState {
    Active(ActiveEntry),
    Transitioning { previous: Option<ActiveEntry> },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RouteTransition {
    route: PrincipalRoute,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Activation {
    pub route: PrincipalRoute,
    pub connection_instance: ConnectionInstanceId,
    pub replaced: Option<ConnectionInstanceId>,
}

impl fmt::Debug for Activation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Activation")
            .field("route", &self.route)
            .field("replaced", &self.replaced.is_some())
            .finish_non_exhaustive()
    }
}

pub(super) struct ActiveConnectionRegistry {
    max_active: usize,
    inner: Mutex<HashMap<PrincipalRoute, ActiveState>>,
}

impl fmt::Debug for ActiveConnectionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveConnectionRegistry")
            .field("max_active", &self.max_active)
            .finish_non_exhaustive()
    }
}

impl ActiveConnectionRegistry {
    pub(super) fn new(max_active: usize) -> Result<Self, RelayFailure> {
        if max_active == 0 {
            return Err(failure(
                RELAY_QUOTA_EXCEEDED,
                "active connection capacity is unavailable",
            ));
        }
        Ok(Self {
            max_active,
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// 在可能改变持久 authority/tombstone 之前先把 route 置为 Transitioning。Core 的
    /// `is_current` 从这一刻起 fail-closed；Store 失败时可恢复仍存活的 previous entry。
    pub(super) fn begin_transition(
        &self,
        route: PrincipalRoute,
        require_capacity: bool,
    ) -> Result<RouteTransition, RelayFailure> {
        let mut active = self.lock()?;
        let previous = match active.get(&route).copied() {
            Some(ActiveState::Active(entry)) => Some(entry),
            Some(ActiveState::Transitioning { .. }) => {
                return Err(failure(
                    RELAY_STORE_UNAVAILABLE,
                    "authentication state is unavailable",
                ));
            }
            None if require_capacity && active.len() >= self.max_active => {
                return Err(failure(
                    RELAY_QUOTA_EXCEEDED,
                    "active connection capacity is exhausted",
                ));
            }
            None => None,
        };
        active.insert(route, ActiveState::Transitioning { previous });
        Ok(RouteTransition { route })
    }

    pub(super) fn begin_machine_transition(
        &self,
        machine_route: MachineRouteId,
    ) -> Result<Vec<RouteTransition>, RelayFailure> {
        let mut active = self.lock()?;
        let routes = active
            .iter()
            .filter_map(|(route, state)| {
                let belongs = match route {
                    PrincipalRoute::Machine(machine) => *machine == machine_route,
                    PrincipalRoute::Device {
                        machine_route: machine,
                        ..
                    } => *machine == machine_route,
                };
                (belongs && matches!(state, ActiveState::Active(_))).then_some(*route)
            })
            .collect::<Vec<_>>();
        if active.iter().any(|(route, state)| {
            let belongs = match route {
                PrincipalRoute::Machine(machine) => *machine == machine_route,
                PrincipalRoute::Device {
                    machine_route: machine,
                    ..
                } => *machine == machine_route,
            };
            belongs && matches!(state, ActiveState::Transitioning { .. })
        }) {
            return Err(failure(
                RELAY_STORE_UNAVAILABLE,
                "authentication state is unavailable",
            ));
        }
        for route in &routes {
            if let Some(ActiveState::Active(previous)) = active.get(route).copied() {
                active.insert(
                    *route,
                    ActiveState::Transitioning {
                        previous: Some(previous),
                    },
                );
            }
        }
        Ok(routes
            .into_iter()
            .map(|route| RouteTransition { route })
            .collect())
    }

    /// Store COMMIT 已完成后，在同一个无 await 的 actor poll 中落 active replacement。
    pub(super) fn commit_transition(
        &self,
        transition: RouteTransition,
        access: &AccessContext,
    ) -> Result<Activation, RelayFailure> {
        let (route, connection_instance, authority, credential_hash) = match access {
            AccessContext::Machine(access) => (
                PrincipalRoute::Machine(access.machine_route),
                access.connection_instance,
                access.link_generation.value(),
                access.cert_hash,
            ),
            AccessContext::Device(access) => (
                PrincipalRoute::Device {
                    machine_route: access.machine_route,
                    device_route: access.device_route,
                },
                access.connection_instance,
                access.grant_serial.value(),
                access.grant_hash,
            ),
            AccessContext::Pairing(_) => {
                return Err(failure(
                    RELAY_ROUTE_FORBIDDEN,
                    "pairing access is not an authenticated principal generation",
                ));
            }
        };
        if route != transition.route {
            return Err(failure(
                RELAY_STORE_UNAVAILABLE,
                "authentication state is unavailable",
            ));
        }
        let mut active = self.lock()?;
        let previous = match active.get(&route).copied() {
            Some(ActiveState::Transitioning { previous }) => previous,
            _ => {
                return Err(failure(
                    RELAY_STORE_UNAVAILABLE,
                    "authentication state is unavailable",
                ));
            }
        };
        let replaced = match previous {
            Some(current) if authority < current.authority => {
                return Err(failure(
                    RELAY_AUTH_INVALID_GRANT,
                    "authentication credential is invalid",
                ));
            }
            Some(current)
                if authority == current.authority && credential_hash != current.credential_hash =>
            {
                return Err(failure(
                    RELAY_AUTH_INVALID_GRANT,
                    "authentication credential is invalid",
                ));
            }
            Some(current) if current.connection_instance == connection_instance => None,
            Some(current) => Some(current.connection_instance),
            None => None,
        };
        active.insert(
            route,
            ActiveState::Active(ActiveEntry {
                connection_instance,
                authority,
                credential_hash,
            }),
        );
        Ok(Activation {
            route,
            connection_instance,
            replaced,
        })
    }

    pub(super) fn abort_transition(&self, transition: RouteTransition) -> Result<(), RelayFailure> {
        let mut active = self.lock()?;
        match active.get(&transition.route).copied() {
            Some(ActiveState::Transitioning {
                previous: Some(previous),
            }) => {
                active.insert(transition.route, ActiveState::Active(previous));
                Ok(())
            }
            Some(ActiveState::Transitioning { previous: None }) => {
                active.remove(&transition.route);
                Ok(())
            }
            _ => Err(failure(
                RELAY_STORE_UNAVAILABLE,
                "authentication state is unavailable",
            )),
        }
    }

    pub(super) fn abort_machine_transition(
        &self,
        transitions: &[RouteTransition],
    ) -> Result<(), RelayFailure> {
        for transition in transitions {
            self.abort_transition(*transition)?;
        }
        Ok(())
    }

    pub(super) fn complete_invalidation(
        &self,
        transition: RouteTransition,
    ) -> Result<Option<ConnectionInstanceId>, RelayFailure> {
        let mut active = self.lock()?;
        match active.remove(&transition.route) {
            Some(ActiveState::Transitioning { previous }) => {
                Ok(previous.map(|entry| entry.connection_instance))
            }
            state => {
                if let Some(state) = state {
                    active.insert(transition.route, state);
                }
                Err(failure(
                    RELAY_STORE_UNAVAILABLE,
                    "authentication state is unavailable",
                ))
            }
        }
    }

    pub(super) fn complete_machine_invalidation(
        &self,
        transitions: &[RouteTransition],
    ) -> Result<Vec<ConnectionInstanceId>, RelayFailure> {
        let mut removed = Vec::with_capacity(transitions.len());
        for transition in transitions {
            if let Some(connection) = self.complete_invalidation(*transition)? {
                removed.push(connection);
            }
        }
        Ok(removed)
    }

    pub(super) fn fail_closed_all(&self) -> Result<Vec<ConnectionInstanceId>, RelayFailure> {
        let mut active = self.lock()?;
        let mut removed = Vec::with_capacity(active.len());
        for (_, state) in active.drain() {
            match state {
                ActiveState::Active(entry) => removed.push(entry.connection_instance),
                ActiveState::Transitioning {
                    previous: Some(entry),
                } => removed.push(entry.connection_instance),
                ActiveState::Transitioning { previous: None } => {}
            }
        }
        Ok(removed)
    }

    pub(super) fn remove_if_current(
        &self,
        route: PrincipalRoute,
        connection_instance: ConnectionInstanceId,
    ) -> Result<bool, RelayFailure> {
        let mut active = self.lock()?;
        let is_current = match active.get_mut(&route) {
            Some(ActiveState::Active(entry))
                if entry.connection_instance == connection_instance =>
            {
                active.remove(&route);
                true
            }
            Some(ActiveState::Transitioning { previous })
                if previous
                    .is_some_and(|entry| entry.connection_instance == connection_instance) =>
            {
                *previous = None;
                true
            }
            _ => false,
        };
        if is_current {
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn current(
        &self,
        route: PrincipalRoute,
    ) -> Result<Option<ConnectionInstanceId>, RelayFailure> {
        Ok(self.lock()?.get(&route).and_then(|state| match state {
            ActiveState::Active(entry) => Some(entry.connection_instance),
            ActiveState::Transitioning { .. } => None,
        }))
    }

    /// P2.3 core 必须在 actor 出队时再次调用，防止 replacement 前已排队的旧 frame
    /// 在新 generation 上线后继续改变订阅或路由状态。
    pub(super) fn is_current(&self, access: &AccessContext) -> Result<bool, RelayFailure> {
        let Some(route) = access.principal_route() else {
            return Ok(false);
        };
        Ok(self.current(route)? == Some(access.connection_instance()))
    }

    /// 在 active-registry mutex 内把 current 检查与一个无等待动作线性化。数据面 fan-out
    /// 用它保证 enqueue 与 revoke/replacement transition 有明确先后，不留下 check/use 窗口。
    pub(super) fn with_current<T>(
        &self,
        access: &AccessContext,
        action: impl FnOnce() -> T,
    ) -> Result<Option<T>, RelayFailure> {
        let Some(route) = access.principal_route() else {
            return Ok(None);
        };
        let active = self.lock()?;
        let is_current = matches!(
            active.get(&route),
            Some(ActiveState::Active(entry))
                if entry.connection_instance == access.connection_instance()
        );
        if is_current {
            Ok(Some(action()))
        } else {
            Ok(None)
        }
    }

    /// 在线 request/reply 同时依赖 origin 与 target 两个 active generation。两侧检查与
    /// writer enqueue 必须共用同一 registry 临界区，任一 transition fence 建立后都不能
    /// 再让旧 generation 跨出 frame。
    pub(super) fn with_both_current<T>(
        &self,
        first: &AccessContext,
        second: &AccessContext,
        action: impl FnOnce() -> T,
    ) -> Result<(bool, bool, Option<T>), RelayFailure> {
        let (Some(first_route), Some(second_route)) =
            (first.principal_route(), second.principal_route())
        else {
            return Ok((false, false, None));
        };
        let active = self.lock()?;
        let first_current = matches!(
            active.get(&first_route),
            Some(ActiveState::Active(entry))
                if entry.connection_instance == first.connection_instance()
        );
        let second_current = matches!(
            active.get(&second_route),
            Some(ActiveState::Active(entry))
                if entry.connection_instance == second.connection_instance()
        );
        if first_current && second_current {
            Ok((true, true, Some(action())))
        } else {
            Ok((first_current, second_current, None))
        }
    }

    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<PrincipalRoute, ActiveState>>, RelayFailure> {
        self.inner.lock().map_err(|_| {
            failure(
                RELAY_STORE_UNAVAILABLE,
                "authentication state is unavailable",
            )
        })
    }
}

fn failure(code: &'static str, message: &'static str) -> RelayFailure {
    RelayFailure::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(seed: u8) -> MachineRouteId {
        MachineRouteId::from_bytes([seed; 16])
    }

    fn device(seed: u8) -> DeviceRouteId {
        DeviceRouteId::from_bytes([seed; 16])
    }

    fn connection(value: u128) -> ConnectionInstanceId {
        ConnectionInstanceId::from_bytes(value.to_be_bytes())
    }

    fn machine_access(
        route: MachineRouteId,
        instance: u128,
        generation: u64,
        hash: u8,
    ) -> AccessContext {
        AccessContext::Machine(MachineAccess {
            machine_route: route,
            connection_instance: connection(instance),
            trust_epoch: TrustEpoch::new(1),
            link_generation: LinkGeneration::new(generation),
            cert_hash: [hash; 32],
        })
    }

    fn activate(
        registry: &ActiveConnectionRegistry,
        access: &AccessContext,
    ) -> Result<Activation, RelayFailure> {
        let route = access.principal_route().expect("principal route");
        let transition = registry.begin_transition(route, true)?;
        let result = registry.commit_transition(transition, access);
        if result.is_err() {
            registry.abort_transition(transition)?;
        }
        result
    }

    #[test]
    fn registry_rejects_late_lower_conflict_and_stale_disconnect() {
        let registry = ActiveConnectionRegistry::new(4).expect("registry");
        let route = machine(1);
        let lower = machine_access(route, 1, 1, 1);
        let reconnect = machine_access(route, 3, 1, 1);
        let higher = machine_access(route, 2, 2, 2);

        activate(&registry, &lower).expect("lower first");
        assert_eq!(
            activate(&registry, &reconnect)
                .expect("same generation/hash reconnect")
                .replaced,
            Some(connection(1))
        );
        assert_eq!(
            activate(&registry, &higher)
                .expect("higher replaces")
                .replaced,
            Some(connection(3))
        );
        assert_eq!(
            activate(&registry, &lower)
                .expect_err("late lower cannot replace")
                .code,
            RELAY_AUTH_INVALID_GRANT
        );
        assert!(
            !registry
                .remove_if_current(PrincipalRoute::Machine(route), connection(1))
                .expect("stale disconnect")
        );

        let conflict = machine_access(route, 4, 2, 9);
        assert_eq!(
            activate(&registry, &conflict)
                .expect_err("same authority different credential")
                .code,
            RELAY_AUTH_INVALID_GRANT
        );

        let device_access = AccessContext::Device(DeviceAccess {
            machine_route: route,
            device_route: device(1),
            connection_instance: connection(5),
            grant_serial: GrantSerial::new(2),
            grant_hash: [5; 32],
            device_sign_fingerprint: [6; 32],
        });
        activate(&registry, &device_access).expect("machine/device namespaces are independent");
        assert!(registry.is_current(&higher).expect("machine remains"));
        assert!(registry.is_current(&device_access).expect("device current"));
    }

    #[test]
    fn access_debug_redacts_route_and_credential_material() {
        let access = machine_access(machine(0xaa), u128::MAX, 1, 0xbb);
        let rendered = format!("{access:?}");
        assert!(!rendered.contains(&format!("{:?}", [0xaa_u8; 16])));
        assert!(!rendered.contains(&"aa".repeat(16)));
        assert!(!rendered.contains(&"bb".repeat(32)));
    }

    #[test]
    fn with_current_linearizes_action_against_transition_fence() {
        let registry = ActiveConnectionRegistry::new(2).expect("registry");
        let route = machine(0xab);
        let access = machine_access(route, 9, 1, 0xcd);
        activate(&registry, &access).expect("activate");
        let calls = std::cell::Cell::new(0_u8);
        assert_eq!(
            registry
                .with_current(&access, || calls.set(calls.get() + 1))
                .expect("current action"),
            Some(())
        );
        let transition = registry
            .begin_transition(PrincipalRoute::Machine(route), false)
            .expect("begin transition");
        assert_eq!(
            registry
                .with_current(&access, || calls.set(calls.get() + 1))
                .expect("fenced action"),
            None
        );
        assert_eq!(calls.get(), 1);
        registry
            .abort_transition(transition)
            .expect("restore active entry");
        assert!(registry.is_current(&access).expect("restored"));
    }

    #[test]
    fn with_both_current_fences_either_side_before_cross_principal_delivery() {
        let registry = ActiveConnectionRegistry::new(2).expect("registry");
        let machine_route = machine(0xbc);
        let machine_access = machine_access(machine_route, 10, 1, 0xde);
        let device_access = AccessContext::Device(DeviceAccess {
            machine_route,
            device_route: device(2),
            connection_instance: connection(11),
            grant_serial: GrantSerial::new(1),
            grant_hash: [0xef; 32],
            device_sign_fingerprint: [0xf0; 32],
        });
        activate(&registry, &machine_access).expect("activate machine");
        activate(&registry, &device_access).expect("activate device");
        let calls = std::cell::Cell::new(0_u8);
        assert_eq!(
            registry
                .with_both_current(&machine_access, &device_access, || {
                    calls.set(calls.get() + 1)
                })
                .expect("both-current action"),
            (true, true, Some(()))
        );

        let device_transition = registry
            .begin_transition(
                device_access.principal_route().expect("device route"),
                false,
            )
            .expect("fence device");
        assert_eq!(
            registry
                .with_both_current(&machine_access, &device_access, || {
                    calls.set(calls.get() + 1)
                })
                .expect("target-fenced action"),
            (true, false, None)
        );
        registry
            .abort_transition(device_transition)
            .expect("restore device");

        let machine_transition = registry
            .begin_transition(
                machine_access.principal_route().expect("machine route"),
                false,
            )
            .expect("fence machine");
        assert_eq!(
            registry
                .with_both_current(&machine_access, &device_access, || {
                    calls.set(calls.get() + 1)
                })
                .expect("origin-fenced action"),
            (false, true, None)
        );
        assert_eq!(calls.get(), 1);
        registry
            .abort_transition(machine_transition)
            .expect("restore machine");
    }

    #[test]
    fn disconnect_during_failed_transition_is_not_resurrected() {
        let registry = ActiveConnectionRegistry::new(2).expect("registry");
        let route = machine(2);
        let access = machine_access(route, 6, 1, 7);
        activate(&registry, &access).expect("activate");
        let transition = registry
            .begin_transition(PrincipalRoute::Machine(route), true)
            .expect("begin transition");
        assert!(!registry.is_current(&access).expect("transition fenced"));
        assert!(
            registry
                .remove_if_current(PrincipalRoute::Machine(route), connection(6))
                .expect("disconnect previous during transition")
        );
        registry
            .abort_transition(transition)
            .expect("Store failure abort");
        assert_eq!(
            registry
                .current(PrincipalRoute::Machine(route))
                .expect("current"),
            None
        );
    }
}
