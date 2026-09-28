//! 桌面端外壳：全高侧栏 + 主区，主区在空态、会话态和机器管理页之间切换。
//!
//! 会话列表和会话记录来自本机与经 ssh 连接的远端 `agentdeckd`，通过 `daemon`
//! 模块按机器、按 agent 拉取；本期只读历史，不启动 session、不发 turn。

use std::collections::VecDeque;
use std::rc::Rc;
use std::time::{Duration, Instant};

use agentdeck_protocol::{
    AgentKind, HistoryListItem, HistoryWarning, MAX_HISTORY_LIST_LIMIT, ThreadId,
};
use gpui::{
    App, Context, Entity, FocusHandle, IntoElement, ListAlignment, ListState, ParentElement,
    ScrollStrategy, SharedString, UniformListScrollHandle, Window, div, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, InteractiveElementExt, Sizable, StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{InputEvent, InputState},
    v_flex,
};

use crate::daemon;
use crate::machines;
use crate::remotes;
use crate::sidebar;
use crate::transcript;
use crate::versions;

/// 首屏和每次扩展的显示条数；多读一条用于判断是否还有会话。
const SIDEBAR_LIMIT: usize = 50;

/// 会话来源机器：`None` 是本机，`Some(host)` 是经 ssh 连接的远端。
pub type Host = Option<SharedString>;

/// 会话身份：不同机器上的 thread id 不保证唯一。
pub type SessionKey = (Host, AgentKind, ThreadId);

fn host_str(host: &Host) -> Option<&str> {
    host.as_ref().map(AsRef::as_ref)
}

pub fn machine_label(host: &Host) -> SharedString {
    host.clone().unwrap_or_else(|| "本机".into())
}

/// 侧栏里的一条会话：来源机器 + daemon 返回的历史条目。
#[derive(Clone)]
pub struct Session {
    pub host: Host,
    pub item: HistoryListItem,
}

impl Session {
    pub fn key(&self) -> SessionKey {
        (
            self.host.clone(),
            self.item.agent_kind,
            self.item.thread_id.clone(),
        )
    }

    pub fn is(&self, key: &SessionKey) -> bool {
        self.host == key.0 && self.item.agent_kind == key.1 && self.item.thread_id == key.2
    }
}

/// 主区当前展示的形态。
pub enum Stage {
    /// 空态：居中大标题、只读提示和本机 agent 过滤卡片。
    Empty,
    /// 会话态：thread header、会话记录和底部只读提示。
    Session {
        session: Session,
        transcript: Transcript,
        /// 会话记录的虚拟列表状态（滚动位置、已测量的块高）；每次读取完成时重置。
        list: ListState,
        read_id: u64,
    },
    /// 机器管理页：添加远端、查看每台机器与各 agent 的连接状态。
    Machines,
}

/// 虚拟列表在可见区上下额外排版的高度，避免快速滚动时出现空白。
const TRANSCRIPT_OVERDRAW: f32 = 1000.;

fn transcript_list() -> ListState {
    ListState::new(0, ListAlignment::Top, px(TRANSCRIPT_OVERDRAW))
}

/// 选中会话的记录加载状态。
pub enum Transcript {
    Loading,
    Ready {
        blocks: Rc<[transcript::Block]>,
        warnings: Vec<HistoryWarning>,
    },
    Failed(String),
}

impl Stage {
    fn finish_read(
        &mut self,
        completed_id: u64,
        read: Result<(Vec<transcript::Block>, Vec<HistoryWarning>), String>,
    ) -> bool {
        if let Stage::Session {
            transcript,
            list,
            read_id,
            ..
        } = self
            && *read_id == completed_id
        {
            *transcript = match read {
                Ok((turns, warnings)) => {
                    list.reset(turns.len());
                    Transcript::Ready {
                        blocks: turns.into(),
                        warnings,
                    }
                }
                Err(message) => Transcript::Failed(message),
            };
            return true;
        }
        false
    }

    pub fn key(&self) -> Option<SessionKey> {
        match self {
            Stage::Empty | Stage::Machines => None,
            Stage::Session { session, .. } => Some(session.key()),
        }
    }
}

struct ReadRequest {
    id: u64,
    client: daemon::Client,
    kind: AgentKind,
    thread_id: ThreadId,
}

#[derive(Default)]
struct ReadQueue {
    active: bool,
    pending: Option<ReadRequest>,
}

impl ReadQueue {
    fn push(&mut self, request: ReadRequest) -> Option<ReadRequest> {
        if self.active {
            self.pending = Some(request);
            None
        } else {
            self.active = true;
            Some(request)
        }
    }

    fn finish(&mut self) -> Option<ReadRequest> {
        let next = self.pending.take();
        self.active = next.is_some();
        next
    }

    fn clear_pending(&mut self) {
        // 执行中的 daemon 仍会正常完成；回到会话时也必须继续受单请求限制。
        self.pending = None;
    }
}

/// 会话标题：历史里没有标题就退回 thread id。
pub fn session_title(item: &HistoryListItem) -> String {
    let title = item.title.as_deref().unwrap_or("").trim();
    if title.is_empty() {
        return item.thread_id.0.clone();
    }
    title.lines().next().unwrap_or(title).trim().to_string()
}

/// 项目名：取 cwd 的最后一段。Claude Code 的 cwd 是从目录名还原的，可能不精确，
/// 因此只用于显示，不用于分组或定位。
pub fn project_name(item: &HistoryListItem) -> String {
    item.cwd
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| item.cwd.display().to_string())
}

/// agent 展示名：直接由中立 `AgentKind` 的 wire 名派生，不按 vendor 分支。
pub fn agent_label(kind: AgentKind) -> String {
    kind.as_str()
        .split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) struct AgentHistory {
    pub kind: AgentKind,
    /// None 表示仍在读取；成功与失败都必须保留来源，不能把失败显示成零条。
    result: Option<Result<(), String>>,
    loaded: usize,
    limit: usize,
    has_more: bool,
    pub warnings: Vec<HistoryWarning>,
    /// CLI 实际安装版本；None 表示仍在查询，查询失败记为 "unknown"。
    pub version: Option<String>,
    pub updating: bool,
    /// 最近一次一键更新的结果：成功为命令输出，失败为错误。
    pub update_result: Option<Result<String, String>>,
}

impl AgentHistory {
    fn new(kind: AgentKind) -> Self {
        Self {
            kind,
            result: None,
            loaded: 0,
            limit: SIDEBAR_LIMIT,
            has_more: false,
            warnings: Vec::new(),
            version: None,
            updating: false,
            update_result: None,
        }
    }

    fn request_limit(&self) -> usize {
        (self.limit + 1).min(MAX_HISTORY_LIST_LIMIT)
    }

    fn complete(
        &mut self,
        listed: &mut Result<(Vec<HistoryListItem>, Vec<HistoryWarning>), String>,
    ) {
        if let Ok((items, warnings)) = listed {
            self.has_more = items.len() > self.limit || items.len() == MAX_HISTORY_LIST_LIMIT;
            items.truncate(self.limit);
            self.loaded = items.len();
            self.warnings = std::mem::take(warnings);
        } else {
            self.warnings.clear();
        }
        self.result = Some(listed.as_ref().map(|_| ()).map_err(Clone::clone));
    }

    pub fn can_load_more(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.has_more && self.limit < MAX_HISTORY_LIST_LIMIT
    }

    fn load_more(&mut self) -> bool {
        if !self.can_load_more() {
            return false;
        }
        // ponytail: 复用有上限的列表查询；数据规模超出 2,000 条时再引入 IPC 游标。
        self.limit = (self.limit + SIDEBAR_LIMIT).min(MAX_HISTORY_LIST_LIMIT);
        self.result = None;
        true
    }

    pub fn list_hint(&self) -> Option<&'static str> {
        if !matches!(self.result, Some(Ok(()))) {
            None
        } else if self.loaded == MAX_HISTORY_LIST_LIMIT {
            Some("已达 2,000 条上限")
        } else if !self.has_more {
            Some("已全部加载")
        } else {
            None
        }
    }

    fn retry(&mut self) -> bool {
        if self.error().is_none() {
            return false;
        }
        self.result = None;
        true
    }

    pub fn status(&self) -> String {
        match &self.result {
            None if self.loaded > 0 => format!("已加载 {} · 加载中…", self.loaded),
            None => "读取中…".to_string(),
            Some(Ok(())) => format!("已加载 {} 个会话", self.loaded),
            Some(Err(_)) if self.loaded > 0 => format!("已加载 {} · 加载失败", self.loaded),
            Some(Err(_)) => "读取失败".to_string(),
        }
    }

    pub fn error(&self) -> Option<&str> {
        self.result.as_ref()?.as_ref().err().map(String::as_str)
    }
}

/// 一台机器上的 daemon：AgentList 结果和各 agent 的历史读取状态。
pub(crate) struct Machine {
    /// 每次连接新分配；移除后再添加同名主机，也不会接受旧请求的迟到回复。
    pub id: u64,
    pub host: Host,
    client: daemon::Client,
    pub agents: Vec<AgentHistory>,
    pub connecting: bool,
    /// AgentList 的失败原因；各来源历史的错误由 AgentHistory 保留。
    pub error: Option<String>,
    /// agentdeckd 自身版本；None 表示仍在查询或未连上，查询失败记为 "unknown"。
    pub daemon_version: Option<String>,
    pub daemon_protocol: Option<u64>,
    pub installing: bool,
    /// 最近一次安装 agentdeckd 的结果：成功为新 daemon 的 `--version`，失败为错误。
    pub install_result: Option<Result<String, String>>,
}

impl Machine {
    fn new(id: u64, host: Host) -> Self {
        let client = daemon::Client::new(host_str(&host));
        Self {
            id,
            host,
            client,
            agents: Vec::new(),
            connecting: false,
            error: None,
            daemon_version: None,
            daemon_protocol: None,
            installing: false,
            install_result: None,
        }
    }

    pub fn has_error(&self) -> bool {
        self.error.is_some() || self.agents.iter().any(|agent| agent.error().is_some())
    }

    pub fn can_update_agents(&self) -> bool {
        !self.connecting
            && !self.installing
            && self.daemon_protocol == Some(u64::from(agentdeck_protocol::PROTOCOL_VERSION))
    }

    /// 远端 login PATH 与 `~/.local/bin` 里都找不到 agentdeckd。
    pub fn daemon_missing(&self) -> bool {
        self.error
            .as_deref()
            .is_some_and(|error| error.contains(daemon::DAEMON_MISSING))
    }
}

fn empty_hint(machines: &[Machine], pending: usize, filtered_empty: bool) -> String {
    if filtered_empty {
        return "没有匹配的会话".to_string();
    }
    let agents = || machines.iter().flat_map(|machine| &machine.agents);
    if agents().any(|agent| agent.loaded > 0) {
        return "选择左侧会话查看记录".to_string();
    }
    if pending > 0 {
        return "正在读取会话…".to_string();
    }
    if let Some(machine) = machines.iter().find(|machine| machine.error.is_some()) {
        return format!(
            "{}：{}",
            machine_label(&machine.host),
            machine.error.as_deref().unwrap_or_default()
        );
    }
    if agents().next().is_none() {
        "agentdeckd 没有注册任何 agent".to_string()
    } else {
        "没有可显示的会话".to_string()
    }
}

/// 开发者模式的帧统计：只记录真实发生的绘制，GPUI 按需重绘，空闲时帧率本来就低。
#[derive(Default)]
pub(crate) struct FrameStats {
    frames: VecDeque<Instant>,
}

impl FrameStats {
    /// 记录一帧，返回最近 1s 的帧数和与上一帧的间隔（毫秒）。
    fn record(&mut self, now: Instant) -> (usize, f64) {
        let interval = self
            .frames
            .back()
            .map_or(0.0, |last| now.duration_since(*last).as_secs_f64() * 1000.0);
        self.frames.push_back(now);
        while let Some(first) = self.frames.front()
            && now.duration_since(*first) >= Duration::from_secs(1)
        {
            self.frames.pop_front();
        }
        (self.frames.len(), interval)
    }
}

/// 侧栏列表的一行：日期分组标题，或指向 `Shell::sessions` 的会话。
pub(crate) enum SidebarRow {
    Header(&'static str),
    Session { index: usize, time: SharedString },
}

/// 毫秒时间戳的本地日序号、年、月、日、时、分。零表示 adapter 没有可显示的时间。
/// 偏移取该时刻自己的，夏令时切换当天不会错位。
#[cfg(unix)]
fn local_time(ms: u64) -> Option<(i64, i32, i32, i32, i32, i32)> {
    if ms == 0 {
        return None;
    }
    let secs = (ms / 1000) as libc::time_t;
    // SAFETY: localtime_r 只写入传入的 tm。
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { libc::localtime_r(&secs, &mut tm) };
    Some((
        (secs as i64 + tm.tm_gmtoff as i64).div_euclid(86_400),
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
    ))
}

/// 相对今天的分组；未来时间（时钟偏差）归入今天。
fn day_group(day: i64, today: i64) -> &'static str {
    match today - day {
        ..=0 => "今天",
        1 => "昨天",
        2..=6 => "近 7 天",
        _ => "更早",
    }
}

/// 按标题或项目名（不区分大小写）和来源（机器 + agent）过滤。
fn session_matches(session: &Session, query: &str, source: Option<&(Host, AgentKind)>) -> bool {
    let item = &session.item;
    source.is_none_or(|(host, kind)| session.host == *host && item.agent_kind == *kind)
        && (query.is_empty()
            || session_title(item).to_lowercase().contains(query)
            || project_name(item).to_lowercase().contains(query))
}

/// 已过滤的会话（按最近活动倒序，带本地时间）插入分组标题。
fn sidebar_rows(
    visible: impl IntoIterator<Item = (usize, Option<(i64, i32, i32, i32, i32, i32)>)>,
    today: i64,
    current_year: i32,
) -> Vec<SidebarRow> {
    let mut rows = Vec::new();
    let mut current = None;
    for (index, time) in visible {
        let group = time
            .map(|(day, ..)| day_group(day, today))
            .unwrap_or("更早");
        if current != Some(group) {
            current = Some(group);
            rows.push(SidebarRow::Header(group));
        }
        let time = time
            .map(|(day, year, month, mday, hour, minute)| {
                if today - day <= 1 {
                    format!("{hour:02}:{minute:02}")
                } else if year != current_year {
                    format!("{year}/{month}/{mday}")
                } else {
                    format!("{month}/{mday}")
                }
            })
            .unwrap_or_default();
        rows.push(SidebarRow::Session {
            index,
            time: time.into(),
        });
    }
    rows
}

fn scroll_sidebar_to(rows: &[SidebarRow], scroll: &UniformListScrollHandle, row: usize) {
    let offset = usize::from(row > 0 && matches!(rows[row - 1], SidebarRow::Header(_)));
    scroll.scroll_to_item_with_offset(row, ScrollStrategy::Top, offset);
}

fn sidebar_target(
    sessions: &[&Session],
    cursor: Option<&SessionKey>,
    step: isize,
) -> Option<usize> {
    let last = sessions.len().checked_sub(1)?;
    // 多个来源异步加载会重排列表，游标始终按会话身份定位。
    let current = match cursor {
        Some(key) => sessions.iter().position(|session| session.is(key)),
        None => Some(0),
    };
    match current {
        Some(index) => Some(index.saturating_add_signed(step).min(last)),
        None if step == 0 => None,
        None if step < 0 => Some(last),
        None => Some(0),
    }
}

pub struct Shell {
    pub(crate) stage: Stage,
    /// Some 表示开启开发者模式，右上角显示 FPS。
    frame_stats: Option<FrameStats>,
    next_read_id: u64,
    reads: ReadQueue,
    /// 侧栏搜索框：按标题或项目名过滤会话。
    pub(crate) search: Entity<InputState>,
    /// 只看某台机器上某个 agent 的会话；主页卡片和机器页 agent 行切换。
    pub(crate) agent_filter: Option<(Host, AgentKind)>,
    /// 本机固定在首位，其后是已连接的远端；每台机器各自决定按哪些 agent 拉历史。
    pub(crate) machines: Vec<Machine>,
    next_machine_id: u64,
    /// 所有机器、所有来源合并后的会话，按最近活动倒序。
    pub(crate) sessions: Vec<Session>,
    /// 过滤并分组后的侧栏行；只在会话、搜索词或过滤变化时重建。
    pub(crate) rows: Vec<SidebarRow>,
    pub(crate) sidebar_focus: FocusHandle,
    pub(crate) sidebar_scroll: UniformListScrollHandle,
    sidebar_cursor: Option<SessionKey>,
    /// 尚未返回的 daemon 请求数；用于区分"还在加载"和"确实没有会话"。
    pub(crate) pending: usize,
    /// 机器页"连接远端"表单：输入框和校验或保存失败的提示。
    pub(crate) remote_input: Entity<InputState>,
    pub(crate) remote_error: Option<String>,
    /// ssh config 里的 Host 别名，进入机器页时重读。
    pub(crate) ssh_hosts: Vec<String>,
    /// npm 上各 agent CLI 的最新版本，按返回顺序追加。
    latest: Vec<(AgentKind, Result<String, String>)>,
    latest_requested: bool,
    /// ssh config 快速添加区默认折叠，免得占掉机器列表的位置。
    pub(crate) quick_add_open: bool,
    /// 已点过一次、等待确认的更新按钮；鼠标移开即取消。
    pub(crate) update_armed: Option<(u64, AgentKind)>,
}

impl Shell {
    /// `connect_daemon=false` 用于 selfcheck：只验证 GPUI 起得来，不碰 daemon 和
    /// 本机 vendor 历史。
    pub fn new(
        window: &mut Window,
        connect_daemon: bool,
        dev_mode: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("搜索会话"));
        cx.subscribe(&search, |shell, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                shell.rebuild_rows(cx);
                cx.notify();
            }
        })
        .detach();
        // 打开窗口即可直接搜索。
        search.update(cx, |input, cx| input.focus(window, cx));

        let remote_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("ssh 主机，如 dt 或 user@host"));
        cx.subscribe(&remote_input, |shell, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::PressEnter { .. }) {
                shell.connect_remote(cx);
            }
        })
        .detach();

        let mut shell = Self {
            stage: Stage::Empty,
            frame_stats: dev_mode.then(FrameStats::default),
            next_read_id: 0,
            reads: ReadQueue::default(),
            search,
            agent_filter: None,
            machines: Vec::new(),
            next_machine_id: 0,
            sessions: Vec::new(),
            rows: Vec::new(),
            sidebar_focus: cx.focus_handle(),
            sidebar_scroll: UniformListScrollHandle::new(),
            sidebar_cursor: None,
            pending: 0,
            remote_input,
            remote_error: None,
            ssh_hosts: Vec::new(),
            latest: Vec::new(),
            latest_requested: false,
            quick_add_open: false,
            update_armed: None,
        };
        if connect_daemon {
            shell.add_machine(None, cx);
            for host in remotes::load() {
                shell.add_machine(Some(host.into()), cx);
            }
        }
        if dev_mode {
            // 空闲时每秒补一帧，让 FPS 数字回落到真实值而不是停在最后一次交互。
            cx.spawn(async move |this, cx| {
                loop {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    if this.update(cx, |_, cx| cx.notify()).is_err() {
                        break;
                    }
                }
            })
            .detach();
        }
        shell
    }

    fn machine(&self, id: u64) -> Option<&Machine> {
        self.machines.iter().find(|machine| machine.id == id)
    }

    fn machine_mut(&mut self, id: u64) -> Option<&mut Machine> {
        self.machines.iter_mut().find(|machine| machine.id == id)
    }

    fn add_machine(&mut self, host: Host, cx: &mut Context<Self>) {
        self.next_machine_id += 1;
        let id = self.next_machine_id;
        self.machines.push(Machine::new(id, host));
        self.load_machine(id, cx);
    }

    /// 先问 daemon 注册了哪些 agent，再按 agent 分别拉历史：谁先返回谁先进侧栏，
    /// 慢的来源不挡住快的；每台机器互不阻塞。
    fn load_machine(&mut self, id: u64, cx: &mut Context<Self>) {
        let Some(machine) = self.machine_mut(id) else {
            return;
        };
        machine.connecting = true;
        let client = machine.client.clone();
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let agents = cx
                .background_executor()
                .spawn(async move { client.agent_list() })
                .await;
            this.update(cx, |shell, cx| {
                shell.pending -= 1;
                cx.notify();
                // 机器已被移除：丢弃迟到的回复。
                let Some(machine) = shell.machine_mut(id) else {
                    return;
                };
                machine.connecting = false;
                match agents {
                    Ok(kinds) => {
                        machine.agents = kinds.iter().copied().map(AgentHistory::new).collect();
                        for kind in kinds {
                            shell.load_agent_sessions(id, kind, cx);
                            shell.load_agent_version(id, kind, cx);
                        }
                        shell.load_daemon_version(id, cx);
                    }
                    Err(message) => machine.error = Some(message),
                }
            })
            .ok();
        })
        .detach();
    }

    /// 机器页展示用；失败只影响版本显示，不影响会话读取。
    fn load_agent_version(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(machine) = self.machine(id) else {
            return;
        };
        let client = machine.client.clone();
        cx.spawn(async move |this, cx| {
            let version = cx
                .background_executor()
                .spawn(async move { client.agent_version(kind) })
                .await;
            this.update(cx, |shell, cx| {
                let agent = shell
                    .machine_mut(id)
                    .and_then(|machine| machine.agents.iter_mut().find(|a| a.kind == kind));
                if let Some(agent) = agent {
                    // 查询失败也要明示拿不到，不能留空或显示默认版本。
                    agent.version = Some(version.unwrap_or_else(|_| "unknown".into()));
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    fn load_daemon_version(&mut self, id: u64, cx: &mut Context<Self>) {
        let Some(machine) = self.machine(id) else {
            return;
        };
        let client = machine.client.clone();
        cx.spawn(async move |this, cx| {
            let version = cx
                .background_executor()
                .spawn(async move { client.daemon_info() })
                .await;
            this.update(cx, |shell, cx| {
                if let Some(machine) = shell.machine_mut(id) {
                    let (version, protocol) = match version {
                        Ok((version, protocol)) => (version, Some(protocol)),
                        Err(_) => ("unknown".into(), None),
                    };
                    machine.daemon_version = Some(version);
                    machine.daemon_protocol = protocol;
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    /// 装上与桌面端同版本的预编译 agentdeckd，成功后断开旧连接重新读取。
    pub fn install_daemon(&mut self, id: u64, cx: &mut Context<Self>) {
        let Some(machine) = self.machine_mut(id) else {
            return;
        };
        let Some(host) = machine.host.clone() else {
            return;
        };
        if machine.installing || machine.agents.iter().any(|agent| agent.updating) {
            return;
        }
        machine.installing = true;
        machine.install_result = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { remotes::install_daemon(&host) })
                .await;
            this.update(cx, |shell, cx| {
                let Some(machine) = shell.machine_mut(id) else {
                    return;
                };
                machine.installing = false;
                let ok = result.is_ok();
                machine.install_result = Some(result);
                if ok {
                    machine.client.reset();
                    machine.error = None;
                    machine.daemon_version = None;
                    machine.daemon_protocol = None;
                    shell.load_machine(id, cx);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    pub fn toggle_quick_add(&mut self, cx: &mut Context<Self>) {
        self.quick_add_open = !self.quick_add_open;
        cx.notify();
    }

    /// 更新按钮两段式确认：第一次点击只进入待确认，再点一次才真正更新。
    pub fn click_update(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        if self.update_armed.take() == Some((id, kind)) {
            self.update_agent(id, kind, cx);
        } else {
            self.update_armed = Some((id, kind));
        }
        cx.notify();
    }

    pub fn disarm_update(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        if self.update_armed == Some((id, kind)) {
            self.update_armed = None;
            cx.notify();
        }
    }

    /// 一键更新：跑 CLI 自带的更新命令，完成后重查版本。
    pub fn update_agent(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(machine) = self.machine_mut(id) else {
            return;
        };
        if !machine.can_update_agents() {
            return;
        }
        let client = machine.client.clone();
        let Some(agent) = machine.agents.iter_mut().find(|a| a.kind == kind) else {
            return;
        };
        if agent.updating {
            return;
        }
        agent.updating = true;
        agent.update_result = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { client.agent_update(kind) })
                .await;
            this.update(cx, |shell, cx| {
                let agent = shell
                    .machine_mut(id)
                    .and_then(|machine| machine.agents.iter_mut().find(|a| a.kind == kind));
                if let Some(agent) = agent {
                    agent.updating = false;
                    agent.update_result = Some(result);
                    agent.version = None;
                    shell.load_agent_version(id, kind, cx);
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn load_agent_sessions(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(machine) = self.machine(id) else {
            return;
        };
        let Some(agent) = machine.agents.iter().find(|agent| agent.kind == kind) else {
            return;
        };
        let limit = agent.request_limit();
        let host = machine.host.clone();
        let client = machine.client.clone();
        self.pending += 1;
        cx.spawn(async move |this, cx| {
            let mut listed = cx
                .background_executor()
                .spawn(async move { client.history_list(kind, limit) })
                .await;
            this.update(cx, |shell, cx| {
                shell.pending -= 1;
                cx.notify();
                let Some(machine) = shell.machine_mut(id) else {
                    return;
                };
                if let Some(agent) = machine.agents.iter_mut().find(|agent| agent.kind == kind) {
                    agent.complete(&mut listed);
                }
                if let Ok((items, _)) = listed {
                    shell
                        .sessions
                        .retain(|session| session.host != host || session.item.agent_kind != kind);
                    shell.sessions.extend(items.into_iter().map(|item| Session {
                        host: host.clone(),
                        item,
                    }));
                    shell
                        .sessions
                        .sort_by_key(|s| std::cmp::Reverse(s.item.last_active_ms));
                    shell.rebuild_rows(cx);
                }
            })
            .ok();
        })
        .detach();
    }

    pub fn retry_machine(&mut self, id: u64, cx: &mut Context<Self>) {
        if self
            .machine_mut(id)
            .is_some_and(|machine| machine.error.take().is_some())
        {
            self.load_machine(id, cx);
            cx.notify();
        }
    }

    pub fn retry_agent(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        if self
            .machine_mut(id)
            .and_then(|machine| machine.agents.iter_mut().find(|agent| agent.kind == kind))
            .is_some_and(AgentHistory::retry)
        {
            self.load_agent_sessions(id, kind, cx);
            cx.notify();
        }
    }

    pub fn show_machines(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.stage = Stage::Machines;
        self.reads.clear_pending();
        self.remote_error = None;
        self.ssh_hosts = remotes::ssh_config_hosts();
        self.load_latest_versions(cx);
        self.remote_input
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    /// 各 agent CLI 在 npm 上的最新版本；首次打开机器页时查一次，selfcheck 路径不联网。
    fn load_latest_versions(&mut self, cx: &mut Context<Self>) {
        if std::mem::replace(&mut self.latest_requested, true) {
            return;
        }
        for kind in [AgentKind::Codex, AgentKind::ClaudeCode] {
            cx.spawn(async move |this, cx| {
                let latest = cx
                    .background_executor()
                    .spawn(async move { versions::fetch_latest(kind) })
                    .await;
                this.update(cx, |shell, cx| {
                    shell.latest.push((kind, latest));
                    cx.notify();
                })
                .ok();
            })
            .detach();
        }
    }

    pub fn latest_version(&self, kind: AgentKind) -> Option<&Result<String, String>> {
        self.latest
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, latest)| latest)
    }

    fn save_remotes(&mut self) {
        let hosts: Vec<&str> = self
            .machines
            .iter()
            .filter_map(|machine| host_str(&machine.host))
            .collect();
        self.remote_error = remotes::save(&hosts).err();
    }

    /// 连接输入框里的主机：校验、去重、持久化，然后像本机一样拉取历史。
    pub fn connect_remote(&mut self, cx: &mut Context<Self>) {
        let host = self.remote_input.read(cx).value().trim().to_string();
        self.connect_host(host, cx);
    }

    pub fn is_connected(&self, host: &str) -> bool {
        self.machines
            .iter()
            .any(|machine| host_str(&machine.host) == Some(host))
    }

    pub fn connect_host(&mut self, host: String, cx: &mut Context<Self>) {
        if let Err(message) = daemon::validate_host(&host) {
            self.remote_error = Some(message);
        } else if self.is_connected(&host) {
            self.remote_error = Some(format!("{host} 已连接"));
        } else {
            self.add_machine(Some(host.into()), cx);
            self.save_remotes();
        }
        cx.notify();
    }

    /// 断开远端：移除其会话与状态；正在查看它的会话时回到空态。
    pub fn remove_machine(&mut self, id: u64, cx: &mut Context<Self>) {
        let Some(index) = self.machines.iter().position(|machine| machine.id == id) else {
            return;
        };
        let machine = self.machines.remove(index);
        machine.client.disconnect();
        let host = machine.host;
        self.sessions.retain(|session| session.host != host);
        if self
            .agent_filter
            .as_ref()
            .is_some_and(|(filtered, _)| *filtered == host)
        {
            self.agent_filter = None;
        }
        if self.stage.key().is_some_and(|key| key.0 == host) {
            self.show_empty(cx);
        }
        self.save_remotes();
        self.rebuild_rows(cx);
        cx.notify();
    }

    /// 还能加载更多的来源；有来源过滤时只算该来源。
    pub fn load_more_targets(&self) -> Vec<(u64, AgentKind)> {
        self.machines
            .iter()
            .flat_map(|machine| {
                machine
                    .agents
                    .iter()
                    .filter(|agent| {
                        agent.can_load_more()
                            && self.agent_filter.as_ref().is_none_or(|(host, kind)| {
                                *host == machine.host && *kind == agent.kind
                            })
                    })
                    .map(|agent| (machine.id, agent.kind))
            })
            .collect()
    }

    pub fn load_more(&mut self, cx: &mut Context<Self>) {
        for (id, kind) in self.load_more_targets() {
            if self
                .machine_mut(id)
                .and_then(|machine| machine.agents.iter_mut().find(|agent| agent.kind == kind))
                .is_some_and(AgentHistory::load_more)
            {
                self.load_agent_sessions(id, kind, cx);
            }
        }
        cx.notify();
    }

    pub fn toggle_agent_filter(&mut self, host: Host, kind: AgentKind, cx: &mut Context<Self>) {
        let source = (host, kind);
        self.agent_filter = (self.agent_filter.as_ref() != Some(&source)).then_some(source);
        self.rebuild_rows(cx);
        cx.notify();
    }

    // ponytail: 分组相对重建时刻的“今天”，窗口跨午夜不动时不刷新；需要时加定时重建。
    fn rebuild_rows(&mut self, cx: &App) {
        let query = self.search.read(cx).value().trim().to_lowercase();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        let (today, current_year, ..) = local_time(now).unwrap_or_default();
        self.rows = sidebar_rows(
            self.sessions
                .iter()
                .enumerate()
                .filter(|(_, session)| session_matches(session, &query, self.agent_filter.as_ref()))
                .map(|(index, session)| (index, local_time(session.item.last_active_ms))),
            today,
            current_year,
        );
        let cursor = self.sidebar_cursor.clone();
        if cursor.is_some_and(|cursor| {
            !self.rows.iter().any(|row| {
                matches!(row, SidebarRow::Session { index, .. } if self.sessions[*index].is(&cursor))
            })
        }) {
            self.sidebar_cursor = None;
        }
    }

    /// 可见会话的行号与条目，键盘导航只在这些行之间移动。
    fn visible_rows(&self) -> (Vec<usize>, Vec<&Session>) {
        self.rows
            .iter()
            .enumerate()
            .filter_map(|(row, entry)| match entry {
                SidebarRow::Session { index, .. } => Some((row, &self.sessions[*index])),
                SidebarRow::Header(_) => None,
            })
            .unzip()
    }

    fn retry_transcript(&mut self, cx: &mut Context<Self>) {
        if let Stage::Session {
            session,
            transcript: Transcript::Failed(_),
            ..
        } = &self.stage
        {
            self.open_session(session.clone(), cx);
        }
    }

    /// 键盘光标所在的侧栏行号。
    pub fn sidebar_cursor_row(&self) -> Option<usize> {
        let (rows, items) = self.visible_rows();
        sidebar_target(&items, self.sidebar_cursor.as_ref(), 0).map(|index| rows[index])
    }

    pub fn navigate_sidebar(&mut self, step: isize, cx: &mut Context<Self>) {
        let (rows, items) = self.visible_rows();
        let target = sidebar_target(&items, self.sidebar_cursor.as_ref(), step)
            .map(|index| (rows[index], items[index].key()));
        if let Some((row, key)) = target {
            self.sidebar_cursor = Some(key);
            scroll_sidebar_to(&self.rows, &self.sidebar_scroll, row);
            cx.notify();
        }
    }

    pub fn open_sidebar_cursor(&mut self, cx: &mut Context<Self>) {
        let Some(row) = self.sidebar_cursor_row() else {
            return;
        };
        if let SidebarRow::Session { index, .. } = self.rows[row] {
            scroll_sidebar_to(&self.rows, &self.sidebar_scroll, row);
            self.open_session(self.sessions[index].clone(), cx);
        }
    }

    pub fn open_session(&mut self, session: Session, cx: &mut Context<Self>) {
        let (host, kind, thread_id) = session.key();
        let Some(machine) = self.machines.iter().find(|machine| machine.host == host) else {
            return;
        };
        let client = machine.client.clone();
        self.sidebar_cursor = Some(session.key());
        self.next_read_id += 1;
        let read_id = self.next_read_id;
        self.stage = Stage::Session {
            session,
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id,
        };
        cx.notify();

        if let Some(request) = self.reads.push(ReadRequest {
            id: read_id,
            client,
            kind,
            thread_id,
        }) {
            self.start_read(request, cx);
        }
    }

    fn start_read(&mut self, request: ReadRequest, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let read_id = request.id;
            let read = cx
                .background_executor()
                .spawn(async move {
                    request
                        .client
                        .history_read(request.kind, request.thread_id)
                        .map(|(turns, warnings)| (transcript::prepare(turns), warnings))
                })
                .await;
            this.update(cx, |shell, cx| {
                // 回到同一会话也属于新请求，不能接受上次读取的迟到结果。
                if shell.stage.finish_read(read_id, read) {
                    cx.notify();
                }
                if let Some(next) = shell.reads.finish() {
                    shell.start_read(next, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    pub fn show_empty(&mut self, cx: &mut Context<Self>) {
        self.stage = Stage::Empty;
        self.reads.clear_pending();
        cx.notify();
    }

    fn render_empty(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let multi_machine = self.machines.len() > 1;
        let cards: Vec<_> = self
            .machines
            .iter()
            .flat_map(|machine| {
                machine.agents.iter().map(|agent| {
                    let source = (machine.host.clone(), agent.kind);
                    let selected = self.agent_filter.as_ref() == Some(&source);
                    (source, agent.status(), selected)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(source, status, selected)| {
                connector_card(source, multi_machine, &status, selected, cx)
            })
            .collect();

        let hint = empty_hint(
            &self.machines,
            self.pending,
            !self.sessions.is_empty() && self.rows.is_empty(),
        );

        v_flex()
            .flex_1()
            .h_full()
            .child(sidebar::titlebar_area("empty-titlebar"))
            .child(
                v_flex()
                    .flex_1()
                    .items_center()
                    .justify_center()
                    .gap_8()
                    .px_10()
                    .pb_10()
                    .child(
                        v_flex()
                            .items_center()
                            .gap_2()
                            .child(div().text_3xl().child("今天要做什么？"))
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(hint),
                            ),
                    )
                    .child(
                        h_flex()
                            .flex_wrap()
                            .justify_center()
                            .gap_3()
                            .children(cards),
                    )
                    .child(read_only_notice(cx)),
            )
    }

    fn render_session(
        &self,
        session: &Session,
        transcript: &Transcript,
        list: &ListState,
        read_id: u64,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let item = &session.item;
        let body = match transcript {
            Transcript::Loading => placeholder("正在读取会话记录…", cx).into_any_element(),
            Transcript::Failed(message) => v_flex()
                .flex_1()
                .min_h(px(0.))
                .px_6()
                .py_4()
                .items_center()
                .justify_center()
                .gap_3()
                .child(
                    div()
                        .id("transcript-error")
                        .w_full()
                        .max_w(px(760.))
                        .min_w(px(0.))
                        .min_h(px(0.))
                        .h(px(240.))
                        .overflow_y_scroll()
                        .child(div().w_full().text_sm().child(message.clone())),
                )
                .child(
                    Button::new("retry-transcript")
                        .flex_shrink_0()
                        .label("重试读取")
                        .on_click(cx.listener(|shell, _, _, cx| shell.retry_transcript(cx))),
                )
                .into_any_element(),
            Transcript::Ready { blocks, .. } if blocks.is_empty() => {
                placeholder("这个会话没有可显示的记录", cx).into_any_element()
            }
            Transcript::Ready { blocks, .. } => {
                transcript::render(blocks.clone(), list.clone(), read_id, window, cx)
                    .into_any_element()
            }
        };

        v_flex()
            .flex_1()
            .h_full()
            // 裁剪在这一层：长会话记录不能顶穿底部只读提示。
            .overflow_hidden()
            .child(
                // thread header：左标题，右上环境信息。高度同时吃掉红绿灯占位。
                h_flex()
                    .id("session-titlebar")
                    .w_full()
                    .h(px(52.))
                    .flex_shrink_0()
                    .px_5()
                    .gap_3()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(cx.theme().border)
                    .on_double_click(|_, window: &mut Window, _| window.titlebar_double_click())
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .whitespace_normal()
                            .line_clamp(1)
                            .text_ellipsis()
                            .text_sm()
                            .font_semibold()
                            .child(session_title(item)),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "{} · {} · {}",
                                agent_label(item.agent_kind),
                                project_name(item),
                                machine_label(&session.host)
                            )),
                    ),
            )
            .when_some(
                match transcript {
                    Transcript::Ready { warnings, .. } if !warnings.is_empty() => Some(warnings),
                    _ => None,
                },
                |section, warnings| {
                    let expanded = window.use_keyed_state(
                        SharedString::from(format!("transcript-warning-expanded-{read_id}")),
                        cx,
                        |_, _| false,
                    );
                    let open = *expanded.read(cx);
                    section.child(
                        v_flex()
                            .w_full()
                            .flex_shrink_0()
                            .px_5()
                            .py_1()
                            .bg(crate::theme_tokens::WARN_WEAK)
                            .child(
                                Button::new(("transcript-warning-toggle", read_id))
                                    .ghost()
                                    .xsmall()
                                    .w_full()
                                    .justify_start()
                                    .label(if open {
                                        "▾ 兼容性警告 · 收起详情"
                                    } else {
                                        "▸ 兼容性警告 · 展开详情"
                                    })
                                    .on_click(move |_, _, cx| {
                                        expanded.update(cx, |expanded, cx| {
                                            *expanded = !*expanded;
                                            cx.notify();
                                        });
                                    }),
                            )
                            .when(open, |section| {
                                section.child(
                                    div()
                                        .id(("transcript-warnings", read_id))
                                        .w_full()
                                        .max_h(px(112.))
                                        .overflow_y_scroll()
                                        .px_2()
                                        .pb_2()
                                        .child(v_flex().gap_1().children(warnings.iter().map(
                                            |warning| {
                                                div().text_xs().child(warning.message.clone())
                                            },
                                        ))),
                                )
                            }),
                    )
                },
            )
            .child(body)
            .child(
                // 发送接入前只留一行只读提示；固定高度，不被上方记录挤压。
                h_flex()
                    .w_full()
                    .flex_shrink_0()
                    .justify_center()
                    .py_3()
                    .border_t_1()
                    .border_color(cx.theme().border)
                    .child(read_only_notice(cx)),
            )
    }
}

fn placeholder(text: &str, cx: &App) -> impl IntoElement + use<> {
    v_flex().flex_1().items_center().justify_center().child(
        div()
            .text_sm()
            .text_color(cx.theme().muted_foreground)
            .child(text.to_string()),
    )
}

fn read_only_notice(cx: &App) -> impl IntoElement + use<> {
    div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child("只读历史预览，暂不能发送任务")
}

/// 主页 agent 卡片：点击只看该机器上该 agent 的会话，再点取消。
/// 多台机器时标题带机器名，否则与单机时一致。
fn connector_card(
    (host, kind): (Host, AgentKind),
    show_machine: bool,
    status: &str,
    selected: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let title = if show_machine {
        format!("{} · {}", agent_label(kind), machine_label(&host))
    } else {
        agent_label(kind)
    };
    v_flex()
        .id(SharedString::from(format!(
            "agent-card-{}-{}",
            machine_label(&host),
            kind.as_str()
        )))
        .w(px(220.))
        .gap_1()
        .p_4()
        .rounded_lg()
        .bg(cx.theme().muted)
        .border_1()
        .border_color(if selected {
            cx.theme().ring
        } else {
            cx.theme().border
        })
        .cursor_pointer()
        .hover(|style| style.bg(cx.theme().secondary_hover))
        .on_click(
            cx.listener(move |shell, _, _, cx| shell.toggle_agent_filter(host.clone(), kind, cx)),
        )
        .child(
            h_flex()
                .gap_2()
                .items_center()
                .child(sidebar::agent_icon(kind, false))
                .child(
                    div()
                        .flex_1()
                        .min_w(px(0.))
                        .whitespace_normal()
                        .text_sm()
                        .font_semibold()
                        .child(title),
                ),
        )
        .child(
            div()
                .text_sm()
                .text_color(cx.theme().muted_foreground)
                .child(if selected {
                    format!("{status} · 已筛选")
                } else {
                    status.to_string()
                }),
        )
}

impl Render for Shell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let main = match &self.stage {
            Stage::Empty => self.render_empty(cx).into_any_element(),
            Stage::Machines => machines::render(self, cx).into_any_element(),
            Stage::Session {
                session,
                transcript,
                list,
                read_id,
            } => self
                .render_session(session, transcript, list, *read_id, window, cx)
                .into_any_element(),
        };
        let selected = self.stage.key();

        let fps = self.frame_stats.as_mut().map(|stats| {
            let (fps, interval) = stats.record(Instant::now());
            div()
                .absolute()
                .top_2()
                .right_2()
                .px_2()
                .py_1()
                .rounded_md()
                .bg(gpui::black().opacity(0.6))
                .text_color(gpui::white())
                .text_xs()
                .font_family("Menlo")
                .child(format!("{fps} fps · {interval:.1} ms"))
        });

        h_flex()
            .relative()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(sidebar::render(self, selected, cx))
            .child(main)
            .children(fps)
    }
}

#[cfg(test)]
mod tests {
    use super::sidebar_target;
    use super::{
        AgentHistory, FrameStats, Machine, ReadQueue, ReadRequest, Session, SidebarRow, Stage,
        Transcript, agent_label, day_group, empty_hint, local_time, project_name,
        scroll_sidebar_to, session_matches, session_title, sidebar_rows, transcript_list,
    };
    use crate::daemon;
    use agentdeck_protocol::{AgentKind, HistoryListItem, HistoryWarning, ThreadId};
    use gpui::{ScrollStrategy, UniformListScrollHandle};

    fn warning() -> HistoryWarning {
        HistoryWarning {
            agent_kind: AgentKind::Codex,
            code: "codex-version-unverified".into(),
            message: "当前 Codex 版本未经验证，仍继续读取历史".into(),
        }
    }

    fn item(title: Option<&str>) -> HistoryListItem {
        HistoryListItem {
            thread_id: ThreadId("7330efa6".into()),
            agent_kind: AgentKind::ClaudeCode,
            title: title.map(|title| title.to_string()),
            cwd: "/Users/dev/Documents/AgentDeck".into(),
            last_active_ms: 1_790_058_256_247,
            archived: false,
        }
    }

    fn local(item: HistoryListItem) -> Session {
        Session { host: None, item }
    }

    fn remote(item: HistoryListItem) -> Session {
        Session {
            host: Some("dt".into()),
            item,
        }
    }

    #[test]
    fn navigation_keeps_the_selected_thread() {
        let mut stage = Stage::Empty;
        assert_eq!(stage.key(), None);

        stage = Stage::Session {
            session: remote(item(Some("修复记录收尾"))),
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 1,
        };
        let key = stage.key().unwrap();
        assert_eq!(key.0.as_deref().map(AsRef::as_ref), Some("dt"));
        assert_eq!(key.2.0, "7330efa6");
        // 同一 thread id 在另一台机器上是另一个会话。
        assert!(!local(item(None)).is(&key));
        assert!(remote(item(None)).is(&key));

        stage = Stage::Empty;
        assert_eq!(stage.key(), None);
    }

    #[test]
    fn sidebar_navigation_tracks_identity_across_reordering_and_clamps_at_the_ends() {
        let first = local(item(Some("A")));
        let mut second = local(item(Some("B")));
        second.item.thread_id = ThreadId("second-thread".into());
        let mut other_machine = second.clone();
        other_machine.host = Some("dt".into());
        let cursor = second.key();
        let mut sessions = vec![&first, &second, &other_machine];

        assert_eq!(sidebar_target(&[], None, 1), None);
        assert_eq!(sidebar_target(&sessions, None, 0), Some(0));
        assert_eq!(sidebar_target(&sessions, None, -1), Some(0));
        assert_eq!(sidebar_target(&sessions, None, 1), Some(1));
        assert_eq!(sidebar_target(&sessions, Some(&cursor), -1), Some(0));
        assert_eq!(sidebar_target(&sessions, Some(&cursor), 1), Some(2));

        sessions.swap(0, 1);
        assert_eq!(sidebar_target(&sessions, Some(&cursor), 0), Some(0));
        assert_eq!(sidebar_target(&sessions, Some(&cursor), -1), Some(0));
        sessions.swap(0, 2);
        assert_eq!(sidebar_target(&sessions, Some(&cursor), 1), Some(2));

        sessions.pop();
        assert_eq!(sidebar_target(&sessions, Some(&cursor), 0), None);
        assert_eq!(sidebar_target(&sessions, Some(&cursor), 1), Some(0));
        assert_eq!(sidebar_target(&sessions, Some(&cursor), -1), Some(1));
    }

    #[test]
    fn sidebar_rows_group_by_local_day_and_keep_session_indices() {
        let today = 20_000;
        let rows = sidebar_rows(
            [
                (0, Some((today, 2026, 9, 26, 14, 5))),
                (2, Some((today - 1, 2026, 9, 25, 9, 0))),
                (3, Some((today - 3, 2026, 9, 23, 8, 0))),
                (5, Some((today - 4, 2026, 9, 22, 8, 0))),
                (7, Some((today - 30, 2026, 8, 27, 8, 0))),
            ],
            today,
            2026,
        );
        let flat: Vec<_> = rows
            .iter()
            .map(|row| match row {
                SidebarRow::Header(label) => label.to_string(),
                SidebarRow::Session { index, time } => format!("{index}@{time}"),
            })
            .collect();
        assert_eq!(
            flat,
            [
                "今天",
                "0@14:05",
                "昨天",
                "2@09:00",
                "近 7 天",
                "3@9/23",
                "5@9/22",
                "更早",
                "7@8/27"
            ]
        );
        assert_eq!(day_group(today + 1, today), "今天");
        assert_eq!(day_group(today - 6, today), "近 7 天");
        assert_eq!(day_group(today - 7, today), "更早");
    }

    #[test]
    fn sidebar_rows_do_not_render_epoch_for_unknown_time() {
        assert_eq!(local_time(0), None);
        let rows = sidebar_rows([(0, local_time(0))], 20_000, 2026);
        assert!(matches!(
            rows.as_slice(),
            [SidebarRow::Header("更早"), SidebarRow::Session { time, .. }] if time.is_empty()
        ));
    }

    #[test]
    fn sidebar_rows_show_the_year_except_for_yesterday() {
        let today = 20_000;
        let rows = sidebar_rows(
            [
                (0, Some((today - 1, 2025, 12, 31, 23, 59))),
                (1, Some((today - 2, 2025, 12, 30, 8, 0))),
            ],
            today,
            2026,
        );
        let times: Vec<_> = rows
            .iter()
            .filter_map(|row| match row {
                SidebarRow::Session { time, .. } => Some(time.as_ref()),
                SidebarRow::Header(_) => None,
            })
            .collect();
        assert_eq!(times, ["23:59", "2025/12/30"]);
    }

    #[test]
    fn sidebar_scroll_keeps_the_group_header_above_its_first_session() {
        let rows = [
            SidebarRow::Header("今天"),
            SidebarRow::Session {
                index: 0,
                time: "12:00".into(),
            },
            SidebarRow::Session {
                index: 1,
                time: "11:00".into(),
            },
        ];
        let scroll = UniformListScrollHandle::default();
        for (row, offset) in [(1, 1), (2, 0)] {
            scroll_sidebar_to(&rows, &scroll, row);
            let target = scroll.0.borrow().deferred_scroll_to_item.unwrap();
            assert_eq!(target.item_index, row);
            assert_eq!(target.strategy, ScrollStrategy::Top);
            assert_eq!(target.offset, offset);
        }
    }

    #[test]
    fn session_filter_matches_title_or_project_and_agent() {
        let claude = local(item(Some("Review AgentDeck PR")));
        assert!(session_matches(&claude, "", None));
        assert!(session_matches(&claude, "review", None));
        assert!(session_matches(
            &claude,
            "agentdeck",
            Some(&(None, AgentKind::ClaudeCode))
        ));
        assert!(!session_matches(
            &claude,
            "review",
            Some(&(None, AgentKind::Codex))
        ));
        assert!(!session_matches(
            &claude,
            "review",
            Some(&(Some("dt".into()), AgentKind::ClaudeCode))
        ));
        assert!(!session_matches(&claude, "robodojo", None));
    }

    #[test]
    fn reopening_a_thread_rejects_results_from_its_previous_read() {
        let first = item(Some("A"));
        let mut other = item(Some("B"));
        other.thread_id = ThreadId("other-thread".into());
        let mut stage = Stage::Session {
            session: local(other),
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 2,
        };
        assert!(!stage.finish_read(1, Ok((vec![], vec![warning()]))));

        stage = Stage::Session {
            session: local(first),
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 3,
        };
        let block = crate::transcript::describe(&agentdeck_protocol::AgentItem::AssistantMessage {
            text: "新的 A 记录".into(),
            meta: Default::default(),
        });
        assert!(stage.finish_read(3, Ok((vec![block], vec![warning()]))));
        assert!(!stage.finish_read(1, Err("旧读取超时".into())));
        assert!(!stage.finish_read(1, Ok((vec![], vec![]))));
        assert!(matches!(
            &stage,
            Stage::Session { transcript: Transcript::Ready { blocks, warnings }, list, .. }
                if blocks.len() == 1 && list.item_count() == 1 && warnings == &[warning()]
        ));

        if let Stage::Session {
            read_id,
            transcript,
            ..
        } = &mut stage
        {
            *read_id = 4;
            *transcript = Transcript::Loading;
        }
        assert!(stage.finish_read(4, Ok((vec![], vec![]))));
        assert!(!stage.finish_read(3, Ok((vec![], vec![warning()]))));
        assert!(matches!(
            &stage,
            Stage::Session { transcript: Transcript::Ready { warnings, .. }, .. }
                if warnings.is_empty()
        ));

        stage = Stage::Empty;
        assert!(!stage.finish_read(3, Ok((vec![], vec![]))));
    }

    fn read_request(id: u64, thread: &str) -> ReadRequest {
        ReadRequest {
            id,
            client: daemon::Client::new(None),
            kind: AgentKind::Codex,
            thread_id: ThreadId(thread.into()),
        }
    }

    #[test]
    fn failed_source_can_retry_without_restarting_a_pending_or_successful_read() {
        let mut source = AgentHistory::new(AgentKind::Codex);
        assert!(!source.retry());
        source.complete(&mut Err("timeout".into()));
        assert!(source.retry());
        assert_eq!(source.status(), "读取中…");
        assert!(source.error().is_none());
        assert!(!source.retry());
        source.complete(&mut Err("still unavailable".into()));
        assert!(source.retry());
        source.complete(&mut Ok((vec![item(None)], vec![])));
        assert_eq!(source.status(), "已加载 1 个会话");
        assert!(!source.retry());
    }

    #[test]
    fn load_more_uses_lookahead_and_stops_at_end_or_protocol_limit() {
        for total in [0, 49, 50, 51, 100, 101, 1_999, 2_000, 2_001] {
            let mut source = AgentHistory::new(AgentKind::Codex);
            let mut expected = 50;
            loop {
                assert_eq!(source.limit, expected);
                assert!(!source.load_more());
                let mut listed = Ok((vec![item(None); total.min(source.request_limit())], vec![]));
                source.complete(&mut listed);
                assert_eq!(listed.unwrap().0.len(), total.min(expected));
                assert_eq!(source.loaded, total.min(expected));
                if !source.can_load_more() {
                    assert_eq!(source.loaded, total.min(2_000));
                    assert_eq!(
                        source.list_hint(),
                        Some(if total >= 2_000 {
                            "已达 2,000 条上限"
                        } else {
                            "已全部加载"
                        })
                    );
                    assert!(!source.load_more());
                    break;
                }
                assert!(source.list_hint().is_none());
                assert!(source.load_more());
                expected = (expected + 50).min(2_000);
            }
        }
    }

    #[test]
    fn failed_load_more_keeps_count_and_retries_the_same_limit() {
        let mut source = AgentHistory::new(AgentKind::Codex);
        source.complete(&mut Ok((vec![item(None); 51], vec![warning()])));
        assert_eq!(source.warnings, vec![warning()]);
        assert!(source.load_more());
        assert_eq!(source.status(), "已加载 50 · 加载中…");
        assert_eq!(source.request_limit(), 101);
        assert!(!source.load_more());
        source.complete(&mut Err("timeout".into()));
        assert_eq!(source.status(), "已加载 50 · 加载失败");
        assert_eq!(source.error(), Some("timeout"));
        assert!(source.warnings.is_empty());
        assert_eq!(source.loaded, 50);
        assert!(!source.load_more());
        assert!(source.retry());
        assert_eq!(source.request_limit(), 101);
        assert!(!source.retry());
        source.complete(&mut Ok((vec![item(None); 100], vec![])));
        assert_eq!(source.status(), "已加载 100 个会话");
        assert_eq!(source.list_hint(), Some("已全部加载"));
    }

    #[test]
    fn slow_read_only_runs_the_last_pending_selection() {
        let mut reads = ReadQueue::default();
        let first = reads.push(read_request(1, "A")).unwrap();
        assert_eq!(first.thread_id.0, "A");
        assert!(reads.push(read_request(2, "B")).is_none());
        assert!(reads.push(read_request(3, "C")).is_none());

        let next = reads.finish().unwrap();
        assert_eq!(next.thread_id.0, "C");
        assert_eq!(next.id, 3);
        assert!(reads.active);
        assert!(reads.finish().is_none());
        assert!(!reads.active);

        assert!(reads.push(read_request(4, "A")).is_some());
        assert!(reads.push(read_request(5, "B")).is_none());
        reads.clear_pending();
        assert!(reads.active);
        assert!(reads.finish().is_none());

        assert!(reads.push(read_request(6, "A")).is_some());
        reads.clear_pending();
        assert!(reads.push(read_request(7, "C")).is_none());
        assert_eq!(reads.finish().unwrap().id, 7);
    }

    #[test]
    fn list_warnings_are_replaced_after_each_successful_read() {
        let mut source = AgentHistory::new(AgentKind::Codex);
        for _ in 0..2 {
            source.complete(&mut Ok((vec![item(None)], vec![warning()])));
            assert_eq!(source.status(), "已加载 1 个会话");
            assert_eq!(source.warnings, vec![warning()]);
            assert!(source.error().is_none());
        }
        source.complete(&mut Ok((vec![item(None)], vec![])));
        assert!(source.warnings.is_empty());
        assert_eq!(source.loaded, 1);
    }

    #[test]
    fn machine_error_includes_source_read_failures() {
        let mut machine = Machine::new(1, None);
        machine.agents.push(AgentHistory::new(AgentKind::Codex));
        assert!(!machine.has_error());

        machine.agents[0].complete(&mut Err("历史读取超时".into()));
        assert!(machine.has_error());
        machine.agents[0].complete(&mut Ok((vec![], vec![])));
        assert!(!machine.has_error());

        machine.error = Some("连接失败".into());
        assert!(machine.has_error());
    }

    #[test]
    fn cli_updates_require_a_ready_daemon_with_the_current_protocol() {
        let mut machine = Machine::new(1, None);
        assert!(!machine.can_update_agents());
        machine.daemon_protocol = Some(5);
        assert!(!machine.can_update_agents());
        machine.daemon_protocol = Some(u64::from(agentdeck_protocol::PROTOCOL_VERSION));
        assert!(machine.can_update_agents());
        machine.connecting = true;
        assert!(!machine.can_update_agents());
        machine.connecting = false;
        machine.installing = true;
        assert!(!machine.can_update_agents());
    }

    #[test]
    fn each_agent_keeps_its_loading_failure_and_empty_result_distinct() {
        let mut fast = AgentHistory::new(AgentKind::ClaudeCode);
        let mut slow = AgentHistory::new(AgentKind::Codex);
        fast.complete(&mut Ok((vec![item(None)], vec![])));
        assert_eq!(fast.status(), "已加载 1 个会话");
        assert_eq!(slow.status(), "读取中…");

        slow.complete(&mut Err("历史读取超时".into()));
        assert_eq!(slow.status(), "读取失败");
        assert_eq!(slow.error(), Some("历史读取超时"));
        assert_eq!(fast.status(), "已加载 1 个会话");
        assert_eq!(fast.error(), None);

        fast.complete(&mut Ok((vec![], vec![])));
        assert_eq!(fast.status(), "已加载 0 个会话");
        assert_eq!(slow.error(), Some("历史读取超时"));
    }

    #[test]
    fn empty_hint_does_not_offer_selection_after_failure_and_zero_results() {
        let mut machines = vec![Machine {
            agents: vec![
                AgentHistory::new(AgentKind::Codex),
                AgentHistory::new(AgentKind::ClaudeCode),
            ],
            ..Machine::new(1, None)
        }];
        let agents = &mut machines[0].agents;
        agents[0].complete(&mut Err("历史读取超时".into()));
        assert_eq!(empty_hint(&machines, 1, false), "正在读取会话…");

        machines[0].agents[1].complete(&mut Ok((vec![], vec![])));
        assert_eq!(empty_hint(&machines, 0, false), "没有可显示的会话");

        // 远端连不上时说明是哪台机器；本机有会话后照常提示选择。
        machines.push(Machine {
            error: Some("Permission denied".into()),
            ..Machine::new(2, Some("dt".into()))
        });
        assert_eq!(empty_hint(&machines, 0, false), "dt：Permission denied");

        machines[0].agents[1].complete(&mut Ok((vec![item(None)], vec![])));
        assert_eq!(empty_hint(&machines, 0, false), "选择左侧会话查看记录");
        assert_eq!(empty_hint(&machines, 0, true), "没有匹配的会话");
    }

    #[test]
    fn session_title_falls_back_to_the_thread_id_and_keeps_one_line() {
        assert_eq!(session_title(&item(None)), "7330efa6");
        assert_eq!(session_title(&item(Some("   "))), "7330efa6");
        assert_eq!(session_title(&item(Some("第一行\n第二行"))), "第一行");
    }

    #[test]
    fn project_name_uses_the_last_path_segment() {
        assert_eq!(project_name(&item(None)), "AgentDeck");
    }

    #[test]
    fn agent_label_comes_from_the_neutral_wire_name() {
        assert_eq!(agent_label(AgentKind::Codex), "Codex");
        assert_eq!(agent_label(AgentKind::ClaudeCode), "Claude Code");
    }

    #[test]
    fn frame_stats_counts_frames_within_last_second() {
        use std::time::{Duration, Instant};
        let start = Instant::now();
        let mut stats = FrameStats::default();
        assert_eq!(stats.record(start), (1, 0.0));
        let (fps, interval) = stats.record(start + Duration::from_millis(500));
        assert_eq!(fps, 2);
        assert!((interval - 500.0).abs() < 1e-6);
        // 第一帧已超出 1s 窗口。
        assert_eq!(stats.record(start + Duration::from_millis(1200)).0, 2);
    }
}
