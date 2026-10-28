//! 桌面端外壳：全高侧栏 + 主区，主区在空态、会话态和机器管理页之间切换。
//!
//! 会话列表和会话记录来自本机与经 ssh 连接的远端 `agentdeckd`，通过 `daemon`
//! 模块按机器、按 agent 拉取。会话页底部可以续聊：发送、停止和审批经 daemon
//! 事件流回到 `live` 状态，渲染在历史记录之后。

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentdeck_protocol::{
    ActionKind, ActionRequest, ActionRequestVendor, AgentKind, ClaudeCodePermissionMode,
    ClientCommand, HistoryListItem, HistoryWarning, ImageAttachment, MAX_HISTORY_LIST_LIMIT,
    ServerEvent, SessionCapabilities, ThreadId,
};
use gpui::{
    App, ClipboardEntry, Context, Entity, FocusHandle, Image, IntoElement, ListAlignment,
    ListState, ObjectFit, ParentElement, ScrollHandle, ScrollStrategy, SharedString,
    UniformListScrollHandle, Window, div, img, prelude::*, px,
};
use gpui_component::{
    ActiveTheme, Colorize, Disableable, Icon, InteractiveElementExt, Selectable, Sizable,
    StyledExt,
    button::{Button, ButtonVariants},
    h_flex,
    input::{Input, InputEvent, InputState, Paste},
    menu::{DropdownMenu, PopupMenuItem},
    v_flex,
};

use crate::daemon;
use crate::live::LiveSession;
use crate::machines;
use crate::remotes;
use crate::session_router::SessionRouter;
use crate::sidebar;
use crate::transcript;
use crate::update;
use crate::versions;

gpui::actions!(questions, [NextQuestion, PreviousQuestion]);

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
        /// 新建会话：还没发出首条消息，thread id 是占位，底部显示工作目录输入框。
        draft: bool,
    },
    /// 机器管理页：添加远端、查看每台机器与各 agent 的连接状态。
    Machines,
}

/// 虚拟列表在可见区上下额外排版的高度，避免快速滚动时出现空白。
const TRANSCRIPT_OVERDRAW: f32 = 1000.;

/// 读完历史后的首帧量出全部行高，滚动条才按整段会话算长度；之后增量 splice 不再全量测。
fn transcript_list() -> ListState {
    ListState::new(0, ListAlignment::Top, px(TRANSCRIPT_OVERDRAW)).measure_all()
}

/// 选中会话的记录加载状态。
pub enum Transcript {
    Loading,
    Ready {
        /// 历史块后接本次续聊的 live 块。
        blocks: Rc<[transcript::Block]>,
        /// 只含读回的历史；live 更新时在它后面重新拼接。
        history: Rc<[transcript::Block]>,
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
                    list.reset(transcript::collapsed_indices(&turns).count());
                    let history: Rc<[transcript::Block]> = turns.into();
                    Transcript::Ready {
                        blocks: history.clone(),
                        history,
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

/// 某台机器上出现过的工作目录，按最近活动倒序去重，最多 `limit` 个；不区分 agent。
fn recent_projects(sessions: &[Session], host: &Host, limit: usize) -> Vec<PathBuf> {
    let mut items: Vec<_> = sessions
        .iter()
        .filter(|session| session.host == *host && !session.item.cwd.as_os_str().is_empty())
        .map(|session| (session.item.last_active_ms, &session.item.cwd))
        .collect();
    items.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut projects: Vec<PathBuf> = Vec::new();
    for (_, cwd) in items {
        if !projects.contains(cwd) {
            projects.push(cwd.clone());
            if projects.len() == limit {
                break;
            }
        }
    }
    projects
}

/// 目录名，用作项目按钮和菜单项的主文字。
fn dir_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

/// 超长名字保留首尾、中间省略，免得项目按钮挤占输入框；结尾常是日期或版本，比开头更能区分。
fn middle_ellipsis(name: &str, max: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() <= max {
        return name.to_string();
    }
    let tail = (max - 1) / 2;
    let head = max - 1 - tail;
    let mut short: String = chars[..head].iter().collect();
    short.push('…');
    short.extend(&chars[chars.len() - tail..]);
    short
}

/// 上级目录的简短提示：用户目录缩写成 `~`，用来区分同名项目。
fn parent_hint(path: &Path, home: Option<&Path>) -> String {
    let Some(parent) = path.parent() else {
        return String::new();
    };
    match home.and_then(|home| parent.strip_prefix(home).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".into(),
        Some(rest) => format!("~/{}", rest.display()),
        None => parent.display().to_string(),
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AgentOperation {
    Install,
    Update,
}

impl AgentOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Install => "安装",
            Self::Update => "更新",
        }
    }
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
    capabilities: Option<Result<SessionCapabilities, String>>,
    pub operation: Option<AgentOperation>,
    /// 保留执行的操作，重查版本后仍能正确显示安装或更新结果。
    pub operation_result: Option<(AgentOperation, Result<String, String>)>,
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
            capabilities: None,
            operation: None,
            operation_result: None,
        }
    }

    pub fn next_operation(&self) -> Option<AgentOperation> {
        self.version.as_deref().map(|version| {
            if versions::extract(version).is_some() {
                AgentOperation::Update
            } else {
                AgentOperation::Install
            }
        })
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
        } else if self.limit == MAX_HISTORY_LIST_LIMIT && self.has_more {
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
    /// agentdeckd 自身版本；None 表示仍在查询或未连上，首次查询失败记为 "unknown"。
    pub daemon_version: Option<String>,
    pub daemon_protocol: Option<u64>,
    pub daemon_checking: bool,
    pub daemon_check_error: Option<String>,
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
            daemon_checking: false,
            daemon_check_error: None,
            installing: false,
            install_result: None,
        }
    }

    pub fn has_error(&self) -> bool {
        self.error.is_some() || self.agents.iter().any(|agent| agent.error().is_some())
    }

    fn prepare_agents(&mut self, kinds: &[AgentKind]) {
        self.agents = kinds
            .iter()
            .map(|&kind| AgentHistory {
                loaded: self
                    .agents
                    .iter()
                    .find(|agent| agent.kind == kind)
                    .map_or(0, |agent| agent.loaded),
                ..AgentHistory::new(kind)
            })
            .collect();
    }

    fn supports_interaction(&self) -> bool {
        self.daemon_protocol == Some(u64::from(agentdeck_protocol::PROTOCOL_VERSION))
    }

    pub fn can_update_agents(&self) -> bool {
        !self.connecting
            && !self.installing
            && !self.daemon_checking
            && self.daemon_protocol == Some(u64::from(agentdeck_protocol::PROTOCOL_VERSION))
    }

    fn complete_daemon_check(&mut self, result: Result<(String, u64), String>) {
        self.daemon_checking = false;
        match result {
            Ok((version, protocol)) => {
                self.daemon_version = Some(version);
                self.daemon_protocol = Some(protocol);
                self.daemon_check_error = None;
            }
            Err(error) => {
                self.daemon_check_error = Some(error);
                self.daemon_version.get_or_insert_with(|| "unknown".into());
            }
        }
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

fn sessions_refresh_ready(pending: usize, machines: &[Machine]) -> bool {
    pending == 0
        && !machines.is_empty()
        && machines.iter().all(|machine| {
            !machine.connecting
                && !machine.installing
                && machine.agents.iter().all(|agent| agent.operation.is_none())
        })
}

fn retain_active_machine_sessions(
    sessions: &mut Vec<Session>,
    host: &Host,
    active_kinds: &[AgentKind],
) {
    sessions.retain(|session| {
        session.host.as_ref() != host.as_ref() || active_kinds.contains(&session.item.agent_kind)
    });
}

fn replace_source_sessions(
    sessions: &mut Vec<Session>,
    live: &[LiveSession],
    host: &Host,
    kind: AgentKind,
    items: Vec<HistoryListItem>,
) -> usize {
    let mut keys = std::collections::HashSet::new();
    let mut replacement: Vec<_> = items
        .into_iter()
        .map(|item| Session {
            host: host.clone(),
            item,
        })
        .filter(|session| keys.insert(session.key()))
        .collect();
    sessions.retain(|session| {
        if session.host.as_ref() != host.as_ref() || session.item.agent_kind != kind {
            return true;
        }
        // 历史快照可能早于新会话落盘，活动会话仍须能从侧栏返回。
        if live
            .iter()
            .any(|live| session.is(&live.key) && live.session_id.is_some())
            && keys.insert(session.key())
        {
            replacement.push(session.clone());
        }
        false
    });
    let loaded = replacement.len();
    sessions.extend(replacement);
    sessions.sort_by_key(|session| std::cmp::Reverse(session.item.last_active_ms));
    loaded
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
fn local_time(ms: u64) -> Option<(i64, i32, i32, i32, i32, i32)> {
    use chrono::{DateTime, Datelike, Local, Timelike};
    if ms == 0 {
        return None;
    }
    let time = DateTime::from_timestamp_millis(i64::try_from(ms).ok()?)?.with_timezone(&Local);
    Some((
        (time.timestamp() + i64::from(time.offset().local_minus_utc())).div_euclid(86_400),
        time.year(),
        time.month() as i32,
        time.day() as i32,
        time.hour() as i32,
        time.minute() as i32,
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
    /// 已点过一次、等待确认的安装或更新按钮；鼠标移开即取消。
    pub(crate) update_armed: Option<(u64, AgentKind, AgentOperation)>,
    /// 续聊过的会话；切走后 daemon 上的会话继续跑，回来还能看到进度。
    /// ponytail: 从不发 SessionClose，vendor 进程随 daemon 退出回收；会话多了再按空闲关闭。
    live: Vec<LiveSession>,
    /// 会话页底部输入框：Enter 发送，⌘Enter（Linux 为 Ctrl+Enter）换行。
    composer: Entity<InputState>,
    /// 粘贴进输入框、随下一轮发出的图片；缩略图用原图渲染。
    attachments: Vec<(Arc<Image>, ImageAttachment)>,
    /// 上一次粘贴图片被拒的原因，下次粘贴或发送时清掉。
    attach_error: Option<String>,
    /// 新建会话的工作目录。
    cwd_input: Entity<InputState>,
    /// 新会话正在手填路径（选了“输入路径…”或没有可选的最近项目）。
    cwd_manual: bool,
    /// 选了“跳过所有权限”，等待二次确认。
    bypass_armed: bool,
    /// 提问卡的键盘焦点；每次新提问自动聚焦一次，按键在卡片上处理。
    question_focus: FocusHandle,
    question_scroll: ScrollHandle,
    /// 已自动聚焦过的提问（requestId, revision）。
    question_focused: Option<(String, u64)>,
    /// 下一帧要聚焦的“其他”输入框（题号）；输入框实体只在渲染时拿得到。
    focus_other: Option<usize>,
    /// 正式 Release 的安装根；本地构建为 None，不检查更新。
    update_root: Option<PathBuf>,
    pub(crate) update: update::Status,
    /// 自更新重启前停留的会话，等历史列表里出现后自动打开。
    reopen: Option<SessionKey>,
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

        let composer = cx.new(|cx| {
            InputState::new(window, cx)
                .auto_grow(1, 8)
                .placeholder(if cfg!(target_os = "macos") {
                    "发消息，Enter 发送，⌘Enter 换行"
                } else {
                    "发消息，Enter 发送，Ctrl+Enter 换行"
                })
        });
        let cwd_input = cx.new(|cx| InputState::new(window, cx).placeholder("工作目录绝对路径"));
        cx.subscribe(&cwd_input, |_, _, event, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        })
        .detach();
        cx.subscribe_in(
            &composer,
            window,
            |shell, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { secondary: false } = event {
                    shell.send_message(window, cx);
                }
            },
        )
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
            live: Vec::new(),
            composer,
            attachments: Vec::new(),
            attach_error: None,
            cwd_input,
            cwd_manual: false,
            bypass_armed: false,
            question_focus: cx.focus_handle(),
            question_scroll: ScrollHandle::new(),
            question_focused: None,
            focus_other: None,
            update_root: None,
            update: update::Status::Idle,
            reopen: None,
        };
        if connect_daemon {
            shell.add_machine(None, cx);
            for host in remotes::load() {
                shell.add_machine(Some(host.into()), cx);
            }
            shell.reopen = update::reopen_arg();
            shell.update_root = update::install_root();
            if let Some(root) = &shell.update_root {
                update::cleanup(root);
                shell.check_updates(cx);
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
        let machine = Machine::new(id, host);
        let events = machine.client.events();
        self.machines.push(machine);
        self.load_machine(id, cx);
        // 机器移除后 Client 释放，读线程结束，通道关闭，这个任务随之退出。
        cx.spawn(async move |this, cx| {
            while let Ok(event) = events.recv().await {
                if this
                    .update(cx, |shell, cx| shell.on_event(id, event, cx))
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
    }

    /// daemon 推回的会话事件：按 sessionId 交给对应的 live 会话。
    fn on_event(&mut self, machine_id: u64, event: ServerEvent, cx: &mut Context<Self>) {
        let Some(host) = self.machine(machine_id).map(|machine| machine.host.clone()) else {
            return;
        };
        let Some(session_id) = crate::live::event_session(&event).cloned() else {
            return;
        };
        let Some(live) = self
            .live
            .iter_mut()
            .find(|live| live.key.0 == host && live.session_id.as_ref() == Some(&session_id))
        else {
            return;
        };
        let adopted = live.adopt_thread(&event);
        let changed = live.apply(event);
        if let Some((old, item)) = adopted {
            let kind = item.agent_kind;
            let session = Session { host, item };
            if let Stage::Session {
                session: current,
                draft,
                ..
            } = &mut self.stage
                && current.is(&old)
            {
                *current = session.clone();
                *draft = false;
                self.sidebar_cursor = Some(session.key());
            }
            self.sessions.insert(0, session);
            if let Some(agent) = self
                .machine_mut(machine_id)
                .and_then(|machine| machine.agents.iter_mut().find(|agent| agent.kind == kind))
            {
                agent.loaded += 1;
            }
            self.rebuild_rows(cx);
            cx.notify();
        }
        if changed {
            self.refresh_live_view(cx);
        }
    }

    /// 本客户端续聊过的会话当前是否在工作；其他客户端或 CLI 里跑的会话看不到。
    pub(crate) fn session_activity(&self, session: &Session) -> Option<crate::live::Activity> {
        self.live
            .iter()
            .find(|live| session.is(&live.key))
            .and_then(LiveSession::activity)
    }

    /// 当前会话页的记录 = 历史块 + live 块；只换 blocks，列表由 render 对账。
    fn refresh_live_view(&mut self, cx: &mut Context<Self>) {
        if let Stage::Session {
            session,
            transcript: Transcript::Ready {
                blocks, history, ..
            },
            ..
        } = &mut self.stage
        {
            let live = self
                .live
                .iter()
                .find(|live| session.is(&live.key))
                .map(|live| transcript::prepare_live(live.turns()))
                .unwrap_or_default();
            *blocks = if live.is_empty() {
                history.clone()
            } else {
                transcript::append(history, live).into()
            };
        }
        cx.notify();
    }

    fn current_live(&mut self) -> Option<(&mut LiveSession, std::path::PathBuf, daemon::Client)> {
        let Stage::Session {
            session,
            transcript: Transcript::Ready { .. },
            ..
        } = &self.stage
        else {
            return None;
        };
        let key = session.key();
        let cwd = session.item.cwd.clone();
        if !self
            .machines
            .iter()
            .any(|machine| machine.host == key.0 && machine.supports_interaction())
        {
            return None;
        }
        let client = self
            .machines
            .iter()
            .find(|machine| machine.host == key.0)?
            .client
            .clone();
        let index = match self.live.iter().position(|live| live.key == key) {
            Some(index) => index,
            None => {
                self.live.push(LiveSession::new(key));
                self.live.len() - 1
            }
        };
        Some((&mut self.live[index], cwd, client))
    }

    /// 写命令可能卡在 ssh 上，放后台；写失败就当这一轮没发出去。
    fn dispatch(&mut self, client: daemon::Client, command: ClientCommand, cx: &mut Context<Self>) {
        let key = self.stage.key();
        cx.spawn(async move |this, cx| {
            let sent = cx
                .background_executor()
                .spawn(async move { client.send(&command) })
                .await;
            if let Err(message) = sent {
                this.update(cx, |shell, cx| {
                    if let Some(live) = shell
                        .live
                        .iter_mut()
                        .find(|live| Some(&live.key) == key.as_ref())
                    {
                        live.send_failed(message);
                    }
                    shell.refresh_live_view(cx);
                })
                .ok();
            }
        })
        .detach();
    }

    /// ⌘V（Linux 为 Ctrl+V）先经过这里：剪贴板是图片就收作附件，否则交给输入框粘贴文字。
    /// gpui 优先读文本，所以同时带文字和图片的剪贴板（如网页复制）只会粘贴文字。
    fn paste_image(&mut self, cx: &mut Context<Self>) {
        let Some(image) = cx.read_from_clipboard().and_then(|item| {
            item.entries().iter().find_map(|entry| match entry {
                ClipboardEntry::Image(image) => Some(image.clone()),
                _ => None,
            })
        }) else {
            return;
        };
        cx.stop_propagation();
        match crate::live::image_attachment(image.format.mime_type(), &image.bytes) {
            Ok(attachment) => {
                self.attachments.push((Arc::new(image), attachment));
                self.attach_error = None;
            }
            Err(error) => self.attach_error = Some(error),
        }
        cx.notify();
    }

    pub fn send_message(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.composer.read(cx).value().trim().to_string();
        if text.is_empty() && self.attachments.is_empty() {
            return;
        }
        let draft = match &mut self.stage {
            Stage::Session {
                session,
                draft: true,
                ..
            } => {
                let cwd = self.cwd_input.read(cx).value().trim().to_string();
                if cwd.is_empty() {
                    return;
                }
                session.item.cwd = cwd.into();
                session.item.title = text
                    .lines()
                    .next()
                    .map(str::to_string)
                    .or_else(|| Some("图片".into()));
                Some(session.item.clone())
            }
            _ => None,
        };
        let initial = match &self.stage {
            Stage::Session { session, .. } => self
                .initial_capabilities(session)
                .and_then(|result| result.as_ref().ok())
                .cloned(),
            _ => None,
        };
        let images = self.attachments.clone();
        let Some((live, cwd, client)) = self.current_live() else {
            return;
        };
        if draft.is_some() && live.session_id.is_none() {
            live.draft = draft;
        }
        let Some(command) = live.send(text, images, cwd, initial.as_ref()) else {
            return;
        };
        self.attachments.clear();
        self.attach_error = None;
        self.composer
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.dispatch(client, command, cx);
        self.refresh_live_view(cx);
    }

    pub fn stop_turn(&mut self, cx: &mut Context<Self>) {
        let Some((live, _, client)) = self.current_live() else {
            return;
        };
        if let Some(command) = live.cancel() {
            self.dispatch(client, command, cx);
        }
    }

    /// 拒绝时输入框里的文字作为反馈交给 agent（计划审批靠它改计划）。
    pub fn decide(
        &mut self,
        approve: bool,
        persist: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let feedback = self.composer.read(cx).value().trim().to_string();
        let message = (!approve && !feedback.is_empty()).then_some(feedback);
        let Some((live, _, client)) = self.current_live() else {
            return;
        };
        if let Some(command) = live.decide(approve, persist, message.clone()) {
            self.dispatch(client, command, cx);
            if message.is_some() {
                self.composer
                    .update(cx, |input, cx| input.set_value("", window, cx));
            }
        }
        cx.notify();
    }

    /// 跳过权限要再确认一次；其余模式直接生效。
    pub fn choose_mode(&mut self, mode: ClaudeCodePermissionMode, cx: &mut Context<Self>) {
        if mode == ClaudeCodePermissionMode::BypassPermissions {
            self.bypass_armed = true;
            cx.notify();
            return;
        }
        self.apply_mode(mode, cx);
    }

    fn confirm_bypass(&mut self, cx: &mut Context<Self>) {
        if self.bypass_armed {
            self.apply_mode(ClaudeCodePermissionMode::BypassPermissions, cx);
        }
    }

    fn apply_mode(&mut self, mode: ClaudeCodePermissionMode, cx: &mut Context<Self>) {
        self.bypass_armed = false;
        let initial = match &self.stage {
            Stage::Session { session, .. } => self
                .initial_capabilities(session)
                .and_then(|result| result.as_ref().ok())
                .cloned(),
            _ => None,
        };
        let Some((live, _, client)) = self.current_live() else {
            return;
        };
        if let Some(command) = live.set_mode(mode, initial.as_ref()) {
            self.dispatch(client, command, cx);
        }
        cx.notify();
    }

    /// 选一个选项（`None` 是“其他”）。单选题选中即进下一页，只有一题时直接提交；
    /// 选“其他”把焦点交给它的输入框。
    pub fn pick_option(&mut self, question: usize, label: Option<String>, cx: &mut Context<Self>) {
        let Some((live, _, _)) = self.current_live() else {
            return;
        };
        let multi = live
            .action()
            .and_then(|action| action.questions.as_ref())
            .and_then(|questions| questions.get(question))
            .is_some_and(|asked| asked.multi_select);
        live.question_tab = question;
        match &label {
            Some(label) => live.toggle_pick(question, label),
            None => live.toggle_other(question),
        }
        let single_question = live.tab_count() == 1;
        let other_on = live.others.get(question).copied().unwrap_or(false);
        if label.is_none() {
            if other_on {
                self.focus_other = Some(question);
            }
        } else if !multi {
            if single_question {
                self.submit_answers(cx);
                return;
            }
            live.step_tab(true);
            self.question_scroll.scroll_to_top_of_item(0);
        }
        cx.notify();
    }

    /// “其他”输入框里按 Enter：回到卡片并前进，和选中单选项一样。
    fn finish_other(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.question_focus);
        let Some((live, _, _)) = self.current_live() else {
            return;
        };
        if live.tab_count() == 1 {
            self.submit_answers(cx);
        } else {
            live.step_tab(true);
            self.question_scroll.scroll_to_top_of_item(0);
            cx.notify();
        }
    }

    pub fn question_tab(&mut self, tab: usize, window: &mut Window, cx: &mut Context<Self>) {
        if let Some((live, _, _)) = self.current_live() {
            live.set_tab(tab);
        }
        self.question_scroll.scroll_to_top_of_item(0);
        window.focus(&self.question_focus);
        cx.notify();
    }

    /// 提问卡键盘：←→/Tab 切页，↑↓ 移动，Enter/空格 选中（汇总页为提交），数字键直选。
    /// 焦点在“其他”输入框里时不处理，按键交给输入框。
    fn question_key(
        &mut self,
        event: &gpui::KeyDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let keystroke = &event.keystroke;
        let modifiers = &keystroke.modifiers;
        if !self.question_focus.is_focused(window)
            || modifiers.control
            || modifiers.alt
            || modifiers.platform
        {
            return;
        }
        let Some((live, _, _)) = self.current_live() else {
            return;
        };
        let tab = live.question_tab;
        let options: Vec<String> = live
            .action()
            .and_then(|action| action.questions.as_ref())
            .and_then(|questions| questions.get(tab))
            .map(|question| question.options.iter().map(|o| o.label.clone()).collect())
            .unwrap_or_default();
        let summary = live.on_summary_tab();
        // 光标位置 / 数字键对应的选项；等于选项数是“其他”。
        let choose = |index: usize| (index <= options.len()).then(|| options.get(index).cloned());
        match keystroke.key.as_str() {
            key @ ("right" | "left") => {
                live.step_tab(key == "right");
                self.question_scroll.scroll_to_top_of_item(0);
            }
            key @ ("up" | "down") if !summary => {
                live.move_cursor(key == "down");
                let row = live.question_cursor + 1;
                // 标题占第 0 行；对齐选项顶部，长说明也不会遮住选项名称。
                self.question_scroll.scroll_to_top_of_item(row);
            }
            "enter" | "space" if summary => self.submit_answers(cx),
            "enter" | "space" => {
                if let Some(choice) = choose(live.question_cursor) {
                    self.pick_option(tab, choice, cx);
                }
            }
            key if !summary && key.len() == 1 && key.as_bytes()[0].is_ascii_digit() => {
                let digit = (key.as_bytes()[0] - b'0') as usize;
                if let Some(choice) = digit.checked_sub(1).and_then(choose) {
                    live.question_cursor = digit - 1;
                    self.question_scroll.scroll_to_top_of_item(digit);
                    self.pick_option(tab, choice, cx);
                }
            }
            _ => return,
        }
        cx.stop_propagation();
        cx.notify();
    }

    pub fn submit_answers(&mut self, cx: &mut Context<Self>) {
        let Some((live, _, client)) = self.current_live() else {
            return;
        };
        match live.answer() {
            Ok(command) => {
                live.error = None;
                self.dispatch(client, command, cx);
            }
            Err(message) => live.error = Some(message),
        }
        self.question_scroll.scroll_to_top_of_item(0);
        cx.notify();
    }

    pub fn cancel_bypass(&mut self, cx: &mut Context<Self>) {
        self.bypass_armed = false;
        cx.notify();
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
                if shell.machine(id).is_none() {
                    return;
                }
                if let Some(machine) = shell.machine_mut(id) {
                    machine.connecting = false;
                }
                match agents {
                    Ok(kinds) => {
                        let host = shell
                            .machine(id)
                            .map_or(None, |machine| machine.host.clone());
                        let active_kinds = kinds.clone();
                        if let Some(machine) = shell.machine_mut(id) {
                            machine.prepare_agents(&kinds);
                        }
                        retain_active_machine_sessions(&mut shell.sessions, &host, &active_kinds);
                        if shell.agent_filter.as_ref().is_some_and(
                            |(filtered_host, filtered_kind)| {
                                filtered_host.as_ref() == host.as_ref()
                                    && !active_kinds.contains(filtered_kind)
                            },
                        ) {
                            shell.agent_filter = None;
                        }
                        shell.rebuild_rows(cx);
                        for kind in kinds {
                            shell.load_agent_sessions(id, kind, cx);
                            shell.load_agent_version(id, kind, cx);
                        }
                        shell.load_daemon_version(id, cx);
                    }
                    Err(message) => {
                        if let Some(machine) = shell.machine_mut(id) {
                            machine.error = Some(message);
                        }
                    }
                }
            })
            .ok();
        })
        .detach();
    }

    fn initial_capabilities(
        &self,
        session: &Session,
    ) -> Option<&Result<SessionCapabilities, String>> {
        self.machines
            .iter()
            .find(|machine| machine.host == session.host)?
            .agents
            .iter()
            .find(|agent| agent.kind == session.item.agent_kind)?
            .capabilities
            .as_ref()
    }

    /// 同一次能力查询供机器页显示版本和首次续聊路由；失败不影响历史读取。
    fn load_agent_version(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(machine) = self.machine_mut(id) else {
            return;
        };
        if let Some(agent) = machine.agents.iter_mut().find(|agent| agent.kind == kind) {
            agent.capabilities = None;
        }
        let client = machine.client.clone();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let capabilities = cx
                .background_executor()
                .spawn(async move { client.agent_capabilities(kind) })
                .await;
            this.update(cx, |shell, cx| {
                let agent = shell
                    .machine_mut(id)
                    .and_then(|machine| machine.agents.iter_mut().find(|a| a.kind == kind));
                if let Some(agent) = agent {
                    // 查询失败也要明示拿不到，不能留空或显示默认版本。
                    agent.version = Some(
                        capabilities
                            .as_ref()
                            .map(|caps| caps.agent_version.clone())
                            .unwrap_or_else(|_| "unknown".into()),
                    );
                    agent.capabilities = Some(capabilities);
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    pub fn load_daemon_version(&mut self, id: u64, cx: &mut Context<Self>) {
        let Some(machine) = self.machine_mut(id) else {
            return;
        };
        if machine.connecting
            || machine.installing
            || machine.daemon_checking
            || machine.agents.iter().any(|agent| agent.operation.is_some())
        {
            return;
        }
        machine.daemon_checking = true;
        machine.daemon_check_error = None;
        let client = machine.client.clone();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let version = cx
                .background_executor()
                .spawn(async move { client.daemon_info() })
                .await;
            this.update(cx, |shell, cx| {
                if let Some(machine) = shell.machine_mut(id) {
                    machine.complete_daemon_check(version);
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
        if machine.connecting
            || machine.installing
            || machine.daemon_checking
            || machine.agents.iter().any(|agent| agent.operation.is_some())
        {
            return;
        }
        machine.installing = true;
        machine.install_result = None;
        machine.daemon_check_error = None;
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

    /// 安装与更新共用两段式确认；版本探测改变操作时必须重新确认。
    pub fn click_update(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        let Some(operation) = self
            .machine(id)
            .and_then(|machine| machine.agents.iter().find(|agent| agent.kind == kind))
            .and_then(AgentHistory::next_operation)
        else {
            return;
        };
        if self.update_armed.take() == Some((id, kind, operation)) {
            self.modify_agent(id, kind, operation, cx);
        } else {
            self.update_armed = Some((id, kind, operation));
        }
        cx.notify();
    }

    pub fn disarm_update(&mut self, id: u64, kind: AgentKind, cx: &mut Context<Self>) {
        if self
            .update_armed
            .is_some_and(|(armed_id, armed_kind, _)| (armed_id, armed_kind) == (id, kind))
        {
            self.update_armed = None;
            cx.notify();
        }
    }

    fn modify_agent(
        &mut self,
        id: u64,
        kind: AgentKind,
        operation: AgentOperation,
        cx: &mut Context<Self>,
    ) {
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
        if agent.operation.is_some() {
            return;
        }
        agent.operation = Some(operation);
        agent.operation_result = None;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    match operation {
                        AgentOperation::Install => client.agent_install(kind),
                        AgentOperation::Update => client.agent_update(kind),
                    }
                })
                .await;
            this.update(cx, |shell, cx| {
                let agent = shell
                    .machine_mut(id)
                    .and_then(|machine| machine.agents.iter_mut().find(|a| a.kind == kind));
                if let Some(agent) = agent {
                    agent.operation = None;
                    agent.operation_result = Some((operation, result));
                    agent.version = None;
                    agent.capabilities = None;
                    shell.load_agent_version(id, kind, cx);
                    shell.load_agent_sessions(id, kind, cx);
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
                    let loaded = replace_source_sessions(
                        &mut shell.sessions,
                        &shell.live,
                        &host,
                        kind,
                        items,
                    );
                    if let Some(agent) = shell
                        .machine_mut(id)
                        .and_then(|machine| machine.agents.iter_mut().find(|a| a.kind == kind))
                    {
                        agent.loaded = loaded;
                    }
                    shell.rebuild_rows(cx);
                    shell.reopen_after_update(cx);
                }
            })
            .ok();
        })
        .detach();
    }

    fn reopen_after_update(&mut self, cx: &mut Context<Self>) {
        let Some(key) = &self.reopen else {
            return;
        };
        if !matches!(self.stage, Stage::Empty) {
            self.reopen = None;
            return;
        }
        if let Some(session) = self.sessions.iter().find(|session| session.is(key)) {
            self.reopen = None;
            self.open_session(session.clone(), cx);
        }
    }

    /// 启动时查一次，之后每 6 小时查一次；失败静默，离线很正常。
    fn check_updates(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            loop {
                let latest = cx
                    .background_executor()
                    .spawn(async { update::fetch_latest() })
                    .await;
                let alive = this.update(cx, |shell, cx| {
                    if let Ok(latest) = latest
                        && update::is_newer(&latest)
                        && matches!(
                            shell.update,
                            update::Status::Idle | update::Status::Available(_)
                        )
                    {
                        shell.update = update::Status::Available(latest);
                        cx.notify();
                    }
                });
                if alive.is_err() {
                    break;
                }
                cx.background_executor()
                    .timer(Duration::from_secs(6 * 60 * 60))
                    .await;
            }
        })
        .detach();
    }

    /// 侧栏更新按钮：下载安装 → 重启（有会话在跑就等空闲）→ 再点一次立即重启。
    pub fn click_app_update(&mut self, cx: &mut Context<Self>) {
        use update::Status::*;
        let Some(root) = self.update_root.clone() else {
            return;
        };
        match self.update.clone() {
            Available(version) | Failed(version, _) => {
                self.update = Installing(version.clone());
                cx.spawn(async move |this, cx| {
                    let installed = cx
                        .background_executor()
                        .spawn({
                            let version = version.clone();
                            async move { update::install(&root, &version) }
                        })
                        .await;
                    this.update(cx, |shell, cx| {
                        shell.update = match installed {
                            Ok(()) => Ready(version),
                            Err(error) => Failed(version, error),
                        };
                        cx.notify();
                    })
                    .ok();
                })
                .detach();
            }
            Ready(version) if self.busy() => {
                self.update = Waiting(version);
                cx.spawn(async move |this, cx| {
                    loop {
                        cx.background_executor().timer(Duration::from_secs(2)).await;
                        let waiting = this.update(cx, |shell, cx| {
                            let waiting = matches!(shell.update, Waiting(_));
                            if waiting && !shell.busy() {
                                shell.restart(cx);
                            }
                            waiting
                        });
                        if !matches!(waiting, Ok(true)) {
                            break;
                        }
                    }
                })
                .detach();
            }
            Ready(_) | Waiting(_) => self.restart(cx),
            Idle | Installing(_) => return,
        }
        cx.notify();
    }

    fn busy(&self) -> bool {
        self.live.iter().any(|live| live.activity().is_some())
    }

    fn restart(&mut self, cx: &mut Context<Self>) {
        let (Some(root), Some(version)) = (&self.update_root, self.update.version()) else {
            return;
        };
        let reopen = match &self.stage {
            Stage::Session { session, .. } => Some(session.key()),
            _ => None,
        };
        match update::relaunch(root, reopen.as_ref()) {
            Ok(()) => cx.quit(),
            Err(error) => {
                self.update = update::Status::Failed(version, format!("重启失败：{error}"));
                cx.notify();
            }
        }
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
        if self.machines[index].installing {
            return;
        }
        let machine = self.machines.remove(index);
        machine.client.disconnect();
        let host = machine.host;
        self.sessions.retain(|session| session.host != host);
        self.live.retain(|live| live.key.0 != host);
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

    pub fn can_refresh_sessions(&self) -> bool {
        sessions_refresh_ready(self.pending, &self.machines)
    }

    pub fn refresh_sessions(&mut self, cx: &mut Context<Self>) {
        if !self.can_refresh_sessions() {
            return;
        }
        let machine_ids: Vec<_> = self.machines.iter().map(|machine| machine.id).collect();
        for id in machine_ids {
            if let Some(machine) = self.machine_mut(id) {
                machine.error = None;
            }
            self.load_machine(id, cx);
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
        if let Some(live) = self.live.iter_mut().find(|live| session.is(&live.key)) {
            live.forget_finished();
        }
        self.bypass_armed = false;
        self.sidebar_cursor = Some(session.key());
        self.next_read_id += 1;
        let read_id = self.next_read_id;
        self.stage = Stage::Session {
            session,
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id,
            draft: false,
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
                    shell.refresh_live_view(cx);
                }
                if let Some(next) = shell.reads.finish() {
                    shell.start_read(next, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    /// 弹出系统目录选择器，选中后回填新会话的工作目录。
    fn pick_cwd(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(gpui::PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("选择".into()),
        });
        cx.spawn_in(window, async move |shell, cx| {
            let Ok(Ok(Some(paths))) = paths.await else {
                return;
            };
            let Some(path) = paths.into_iter().next() else {
                return;
            };
            shell
                .update_in(cx, |shell, window, cx| shell.set_cwd(&path, window, cx))
                .ok();
        })
        .detach();
    }

    fn set_cwd(&mut self, path: &Path, window: &mut Window, cx: &mut Context<Self>) {
        self.cwd_manual = false;
        self.cwd_input.update(cx, |input, cx| {
            input.set_value(path.display().to_string(), window, cx)
        });
        cx.notify();
    }

    fn edit_cwd(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.cwd_manual = true;
        self.cwd_input
            .update(cx, |input, cx| input.focus(window, cx));
        cx.notify();
    }

    /// 在某台机器的某个 agent 上新建会话；工作目录默认取它最近一次会话的。
    pub fn start_draft(
        &mut self,
        host: Host,
        kind: AgentKind,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let cwd = self
            .sessions
            .iter()
            .find(|session| session.host == host && session.item.agent_kind == kind)
            .map(|session| session.item.cwd.display().to_string())
            .or_else(|| {
                host.is_none()
                    .then(crate::platform::home_dir)
                    .flatten()
                    .map(|home| home.display().to_string())
            })
            .unwrap_or_default();
        self.cwd_manual = cwd.is_empty();
        self.cwd_input
            .update(cx, |input, cx| input.set_value(cwd, window, cx));
        self.composer
            .update(cx, |input, cx| input.focus(window, cx));
        self.next_read_id += 1;
        let read_id = self.next_read_id;
        self.bypass_armed = false;
        self.sidebar_cursor = None;
        self.reads.clear_pending();
        let item = HistoryListItem {
            // 占位 id 每次不同，免得两个未开始的新会话共用一个 live 状态。
            thread_id: ThreadId(format!("draft-{read_id}")),
            agent_kind: kind,
            title: Some("新会话".into()),
            cwd: Default::default(),
            last_active_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            archived: false,
        };
        self.stage = Stage::Session {
            session: Session { host, item },
            transcript: Transcript::Ready {
                blocks: Rc::from([]),
                history: Rc::from([]),
                warnings: Vec::new(),
            },
            list: transcript_list(),
            read_id,
            draft: true,
        };
        cx.notify();
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
                    // 已加载完成时大数字已说明一切，只在读取中或失败时补一行状态。
                    let note = (!matches!(agent.result, Some(Ok(())))).then(|| agent.status());
                    let failed = matches!(agent.result, Some(Err(_)));
                    let can_start = machine.supports_interaction();
                    (source, agent.loaded, note, failed, selected, can_start)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(source, loaded, note, failed, selected, can_start)| {
                connector_card(
                    source,
                    multi_machine,
                    loaded,
                    note,
                    failed,
                    selected,
                    can_start,
                    cx,
                )
            })
            .collect();
        // 固定列数的 grid：flex_wrap 会留下孤儿行，且高度计算不可靠。
        let columns = match cards.len() {
            0 | 1 => 1,
            2 | 4 => 2,
            _ => 3,
        };
        let sessions: usize = self
            .machines
            .iter()
            .flat_map(|machine| &machine.agents)
            .map(|agent| agent.loaded)
            .sum();

        let hint = empty_hint(
            &self.machines,
            self.pending,
            !self.sessions.is_empty() && self.rows.is_empty(),
        );
        let accent: gpui::Hsla = crate::theme_tokens::ACCENT.into();

        v_flex()
            .relative()
            .flex_1()
            .min_w(px(0.))
            .h_full()
            .child(
                // 顶部一层极淡的品牌色光晕，给大面积深色一点空气感。
                div()
                    .absolute()
                    .top_0()
                    .left_0()
                    .right_0()
                    .h(px(420.))
                    .bg(gpui::linear_gradient(
                        180.,
                        gpui::linear_color_stop(accent.opacity(0.07), 0.),
                        gpui::linear_color_stop(accent.opacity(0.), 1.),
                    )),
            )
            .child(sidebar::titlebar_area("empty-titlebar"))
            .child(
                v_flex()
                    .id("empty-body")
                    .flex_1()
                    .min_h(px(0.))
                    .overflow_y_scroll()
                    .px_10()
                    .pb_16()
                    .child(
                        v_flex()
                            .w_full()
                            .flex_shrink_0()
                            // 自动外边距只分配剩余高度，内容溢出时从顶部开始滚动。
                            .my_auto()
                            .items_center()
                            .gap_10()
                            .child(
                                v_flex()
                                    .items_center()
                                    .gap_3()
                                    .child(eyebrow(
                                        format!(
                                            "{} 台机器 · {} 个会话",
                                            self.machines.len(),
                                            sessions
                                        ),
                                        cx,
                                    ))
                                    .child(
                                        div()
                                            .text_size(px(40.))
                                            .line_height(px(48.))
                                            .font_semibold()
                                            .child("今天要做什么？"),
                                    )
                                    .child(
                                        div()
                                            .text_base()
                                            .text_color(cx.theme().muted_foreground)
                                            .child(hint),
                                    ),
                            )
                            .child(
                                div()
                                    .grid()
                                    .grid_cols(columns)
                                    .w_full()
                                    .max_w(px(columns as f32 * 232. + (columns - 1) as f32 * 16.))
                                    .gap_4()
                                    .children(cards),
                            )
                            .child(read_only_notice(cx)),
                    ),
            )
    }

    #[allow(clippy::too_many_arguments)]
    fn render_session(
        &self,
        session: &Session,
        transcript: &Transcript,
        list: &ListState,
        read_id: u64,
        draft: bool,
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
            Transcript::Ready { blocks, .. } if blocks.is_empty() => placeholder(
                if draft {
                    "选择项目，发出第一条消息开始新会话"
                } else {
                    "这个会话没有可显示的记录"
                },
                cx,
            )
            .into_any_element(),
            Transcript::Ready { blocks, .. } => transcript::render(
                blocks.clone(),
                item.agent_kind,
                list.clone(),
                read_id,
                window,
                cx,
            )
            .into_any_element(),
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
                        // 元信息拆成标签：agent、项目、机器；长名称截断，不顶出窗口。
                        h_flex()
                            .flex_shrink()
                            .min_w(px(0.))
                            .max_w(px(420.))
                            .gap_1p5()
                            .child(
                                meta_chip(cx)
                                    .flex_shrink_0()
                                    .child(sidebar::agent_icon(item.agent_kind, false))
                                    .child(agent_label(item.agent_kind)),
                            )
                            .child(
                                meta_chip(cx).min_w(px(0.)).child(
                                    div().min_w(px(0.)).truncate().child(project_name(item)),
                                ),
                            )
                            .child(
                                meta_chip(cx).min_w(px(0.)).child(
                                    div()
                                        .min_w(px(0.))
                                        .truncate()
                                        .child(machine_label(&session.host)),
                                ),
                            ),
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
                            .bg(cx.theme().warning.opacity(0.06))
                            .border_b_1()
                            .border_color(crate::theme_tokens::WARN_WEAK)
                            .text_color(cx.theme().warning)
                            .child(
                                h_flex()
                                    .w_full()
                                    .py_0p5()
                                    .gap_2()
                                    .items_center()
                                    .text_xs()
                                    .child(Icon::empty().xsmall().path(crate::ALERT_ICON))
                                    .child(div().font_semibold().child("兼容性警告"))
                                    .child(
                                        div()
                                            .flex_1()
                                            .text_color(cx.theme().warning.opacity(0.7))
                                            .child(format!("{} 条", warnings.len())),
                                    )
                                    .child(
                                        Button::new(("transcript-warning-toggle", read_id))
                                            .ghost()
                                            .xsmall()
                                            .text_color(cx.theme().warning)
                                            .label(if open { "收起" } else { "展开" })
                                            .child(Icon::empty().xsmall().path(if open {
                                                crate::CHEVRON_DOWN_ICON
                                            } else {
                                                crate::CHEVRON_RIGHT_ICON
                                            }))
                                            .on_click(move |_, _, cx| {
                                                expanded.update(cx, |expanded, cx| {
                                                    *expanded = !*expanded;
                                                    cx.notify();
                                                });
                                            }),
                                    ),
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
            .when(matches!(transcript, Transcript::Ready { .. }), |section| {
                section.child(self.render_composer(session, draft, window, cx))
            })
    }

    /// 底部续聊区：待决审批、跳过权限确认、最近错误、权限模式、输入框和发送/停止按钮；
    /// 固定高度，不被记录挤压。
    /// 新会话的项目按钮：只显示目录名，完整路径放悬停提示；下拉列出这台机器的最近项目。
    fn render_project_picker(
        &self,
        session: &Session,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let cwd = PathBuf::from(self.cwd_input.read(cx).value().trim());
        let empty = cwd.as_os_str().is_empty();
        let local = session.host.is_none();
        let home = local.then(crate::platform::home_dir).flatten();
        let projects = recent_projects(&self.sessions, &session.host, 8);
        let muted = cx.theme().muted_foreground;
        let shell = cx.entity().downgrade();
        Button::new("project-picker")
            .small()
            .ghost()
            .icon(Icon::empty().xsmall().path(crate::FOLDER_ICON))
            .label(if empty {
                "选择项目".into()
            } else {
                middle_ellipsis(&dir_name(&cwd), 20)
            })
            .child(Icon::empty().xsmall().path(crate::CHEVRON_DOWN_ICON))
            .when(!empty, |button| button.tooltip(cwd.display().to_string()))
            .dropdown_menu_with_anchor(gpui::Corner::BottomLeft, move |menu, _, _| {
                let mut menu = menu.min_w(px(240.)).max_w(px(360.));
                if !projects.is_empty() {
                    menu = menu.label("最近项目");
                }
                for path in &projects {
                    let name = dir_name(path);
                    let hint = parent_hint(path, home.as_deref());
                    let shell = shell.clone();
                    let target = path.clone();
                    menu = menu.item(
                        PopupMenuItem::element(move |_, _| {
                            v_flex()
                                .min_w_0()
                                .child(div().truncate().child(name.clone()))
                                .child(
                                    div()
                                        .truncate()
                                        .text_xs()
                                        .text_color(muted)
                                        .child(hint.clone()),
                                )
                        })
                        .checked(*path == cwd)
                        .on_click(move |_, window, cx| {
                            let _ =
                                shell.update(cx, |shell, cx| shell.set_cwd(&target, window, cx));
                        }),
                    );
                }
                if !projects.is_empty() {
                    menu = menu.separator();
                }
                // 原生选择器只能浏览本机目录，远端机器只能手填。
                if local {
                    let shell = shell.clone();
                    menu = menu.item(PopupMenuItem::new("浏览…").on_click(move |_, window, cx| {
                        let _ = shell.update(cx, |shell, cx| shell.pick_cwd(window, cx));
                    }));
                }
                let shell = shell.clone();
                menu.item(
                    PopupMenuItem::new("输入路径…").on_click(move |_, window, cx| {
                        let _ = shell.update(cx, |shell, cx| shell.edit_cwd(window, cx));
                    }),
                )
            })
    }

    fn render_composer(
        &self,
        session: &Session,
        draft: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let live = self.live.iter().find(|live| session.is(&live.key));
        let initial_result = self.initial_capabilities(session);
        let initial = initial_result.and_then(|result| result.as_ref().ok());
        let router = match live {
            Some(live) => live.router(initial),
            None => initial.map(SessionRouter),
        };
        let machine = self
            .machines
            .iter()
            .find(|machine| machine.host == session.host);
        let compatible = machine.is_some_and(Machine::supports_interaction);
        let running = live.is_some_and(|live| live.running.is_some());
        let waiting = live.is_some_and(LiveSession::waiting);
        let mode = live.map_or(ClaudeCodePermissionMode::Default, |live| live.mode);
        let modes = if compatible {
            router
                .as_ref()
                .map(|router| router.permission_modes().to_vec())
                .unwrap_or_default()
        } else {
            vec![]
        };
        let shell = cx.entity().downgrade();
        let can_send = compatible
            && live.map_or_else(
                || {
                    router.as_ref().is_some_and(|router| {
                        router.supports_messages() && router.start_options(mode).is_ok()
                    })
                },
                |live| live.can_send(initial),
            );
        // 新会话发出首条消息前可改工作目录。
        let editing_cwd = draft && live.is_none_or(|live| live.session_id.is_none());
        let can_send =
            can_send && !(editing_cwd && self.cwd_input.read(cx).value().trim().is_empty());
        let can_cancel = compatible && live.is_some_and(|live| live.cancel().is_some());
        let project_picker = editing_cwd.then(|| self.render_project_picker(session, cx));
        let retry_capabilities = initial_result
            .filter(|result| result.is_err())
            .and_then(|_| {
                self.machines
                    .iter()
                    .find(|machine| machine.host == session.host)
            })
            .map(|machine| (machine.id, session.item.agent_kind));
        let action = live
            .filter(|_| compatible)
            .and_then(|live| live.action().cloned());
        let error = live.and_then(|live| live.error.clone());
        let notice = if !compatible {
            Some(
                if machine.is_some_and(|machine| machine.daemon_protocol.is_some()) {
                    "daemon 协议不支持会话交互，请在机器页更新或重装 daemon".to_string()
                } else {
                    "正在确认 daemon 协议；检查失败可在机器页重试".to_string()
                },
            )
        } else {
            match &router {
                None if live.is_some_and(|live| live.session_id.is_some()) => {
                    Some("正在建立会话…".to_string())
                }
                None => Some(match initial_result {
                    Some(Err(error)) => format!("无法读取会话能力：{error}"),
                    _ => "正在读取会话能力…".into(),
                }),
                Some(router) if !router.supports_messages() => {
                    Some("当前来源不支持流式续聊".into())
                }
                Some(router) if live.is_none_or(|live| live.session_id.is_none()) => {
                    router.start_options(mode).err()
                }
                _ => None,
            }
        };
        let theme = cx.theme();
        let (border, surface, danger) = (theme.border, theme.secondary, theme.danger);

        v_flex()
            .w_full()
            .flex_shrink_0()
            .items_center()
            .px_6()
            .pt_2()
            .pb_4()
            .gap_2()
            .when_some(notice, |section, notice| {
                section.child(
                    div()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child(notice),
                )
            })
            .when_some(retry_capabilities, |section, (id, kind)| {
                section.child(
                    Button::new("retry-capabilities")
                        .small()
                        .outline()
                        .label("重试读取能力")
                        .on_click(cx.listener(move |shell, _, _, cx| {
                            shell.load_agent_version(id, kind, cx)
                        })),
                )
            })
            .when(editing_cwd && self.cwd_manual, |section| {
                section.child(
                    h_flex()
                        .w_full()
                        .max_w(px(760.))
                        .gap_2()
                        .items_center()
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("工作目录")
                        .child(Input::new(&self.cwd_input).small().flex_1()),
                )
            })
            .when_some(action, |section, action| {
                section.child(self.render_approval(session, &action, window, cx))
            })
            .when(self.bypass_armed, |section| {
                section.child(
                    h_flex()
                        .w_full()
                        .max_w(px(760.))
                        .gap_2()
                        .px_3()
                        .py_2()
                        .items_center()
                        .rounded_lg()
                        .border_1()
                        .border_color(danger.opacity(0.5))
                        .bg(danger.opacity(0.08))
                        .text_sm()
                        .child(div().flex_1().min_w(px(0.)).child(
                            "跳过所有权限后，agent 执行命令、改动文件都不再询问。确定开启？",
                        ))
                        .child(
                            Button::new("cancel-bypass")
                                .small()
                                .outline()
                                .label("取消")
                                .on_click(cx.listener(|shell, _, _, cx| shell.cancel_bypass(cx))),
                        )
                        .child(
                            Button::new("confirm-bypass")
                                .small()
                                .danger()
                                .label("确认开启")
                                .on_click(cx.listener(|shell, _, _, cx| shell.confirm_bypass(cx))),
                        ),
                )
            })
            .when(waiting, |section| {
                // CC 启动时要先跑用户配置的 hook，首个输出可能要等一会儿。
                section.child(
                    div()
                        .w_full()
                        .max_w(px(760.))
                        .text_xs()
                        .text_color(cx.theme().muted_foreground)
                        .child("等待 agent 响应…"),
                )
            })
            .when_some(error.or(self.attach_error.clone()), |section, error| {
                section.child(
                    div()
                        .w_full()
                        .max_w(px(760.))
                        .text_xs()
                        .text_color(danger)
                        .line_clamp(3)
                        .child(error),
                )
            })
            .when(!self.attachments.is_empty(), |section| {
                section.child(
                    h_flex().w_full().max_w(px(760.)).gap_2().children(
                        self.attachments
                            .iter()
                            .enumerate()
                            .map(|(index, (image, _))| {
                                div()
                                    .relative()
                                    .size(px(64.))
                                    .rounded_md()
                                    .overflow_hidden()
                                    .border_1()
                                    .border_color(border)
                                    .child(
                                        img(image.clone()).size_full().object_fit(ObjectFit::Cover),
                                    )
                                    .child(
                                        Button::new(("remove-image", index))
                                            .absolute()
                                            .top_0()
                                            .right_0()
                                            .xsmall()
                                            .ghost()
                                            .label("×")
                                            .on_click(cx.listener(move |shell, _, _, cx| {
                                                shell.attachments.remove(index);
                                                cx.notify();
                                            })),
                                    )
                            }),
                    ),
                )
            })
            .child(
                h_flex()
                    .w_full()
                    .max_w(px(760.))
                    .gap_2()
                    .p_2()
                    .items_center()
                    .rounded_xl()
                    .border_1()
                    .border_color(border)
                    .bg(surface)
                    .when_some(project_picker, |row, picker| row.child(picker))
                    .when(!modes.is_empty(), |row| {
                        row.child(
                            Button::new("permission-mode")
                                .small()
                                .ghost()
                                .label(mode_label(mode))
                                .child(Icon::empty().xsmall().path(crate::CHEVRON_DOWN_ICON))
                                .when(mode == ClaudeCodePermissionMode::BypassPermissions, |b| {
                                    b.text_color(danger)
                                })
                                .dropdown_menu_with_anchor(
                                    gpui::Corner::BottomLeft,
                                    move |menu, _, _| {
                                        modes.iter().fold(menu, |menu, &option| {
                                            let shell = shell.clone();
                                            menu.item(
                                                PopupMenuItem::new(mode_menu_label(option))
                                                    .checked(option == mode)
                                                    .on_click(move |_, _, cx| {
                                                        let _ = shell.update(cx, |shell, cx| {
                                                            shell.choose_mode(option, cx)
                                                        });
                                                    }),
                                            )
                                        })
                                    },
                                ),
                        )
                    })
                    .child(
                        div()
                            .flex_1()
                            .capture_action(
                                cx.listener(|shell, _: &Paste, _, cx| shell.paste_image(cx)),
                            )
                            .child(Input::new(&self.composer).appearance(false).w_full()),
                    )
                    .child(if running {
                        Button::new("stop-turn")
                            .disabled(!can_cancel)
                            .small()
                            .outline()
                            .label("停止")
                            .on_click(cx.listener(|shell, _, _, cx| shell.stop_turn(cx)))
                    } else {
                        Button::new("send-message")
                            .disabled(!can_send)
                            .small()
                            .primary()
                            .label("发送")
                            .on_click(
                                cx.listener(|shell, _, window, cx| shell.send_message(window, cx)),
                            )
                    }),
            )
    }

    /// 审批卡：类型、摘要、可滚动的完整内容和决定按钮。计划审批的“拒绝”是继续规划。
    fn render_approval(
        &self,
        session: &Session,
        action: &ActionRequest,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        if action.questions.is_some() {
            return self.render_questions(session, action, window, cx);
        }
        let plan = matches!(action.kind, ActionKind::ApprovePlan);
        let can_persist = match &action.vendor {
            ActionRequestVendor::Codex { can_persist, .. }
            | ActionRequestVendor::ClaudeCode { can_persist, .. } => *can_persist,
        };
        let detail = action.detail.as_deref().map(|detail| {
            let markdown = match action.kind {
                ActionKind::ApprovePlan => detail.to_string(),
                ActionKind::ExecuteCommand => transcript::fence("bash", detail),
                ActionKind::EditFiles => transcript::fence("diff", detail),
                ActionKind::GrantExtraPermission | ActionKind::AnswerQuestions => {
                    transcript::fence("json", detail)
                }
            };
            transcript::markdown(
                SharedString::from(format!("approval-{}", action.request_id)).into(),
                &markdown.into(),
                &[],
                window,
                cx,
            )
        });
        let theme = cx.theme();
        let (warning, muted) = (theme.warning, theme.muted_foreground);

        v_flex()
            .w_full()
            .max_w(px(760.))
            .gap_2()
            .px_3()
            .py_2()
            .rounded_lg()
            .border_1()
            .border_color(warning.opacity(0.5))
            .bg(warning.opacity(0.08))
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .text_sm()
                    .child(
                        Icon::empty()
                            .xsmall()
                            .path(crate::ALERT_ICON)
                            .text_color(warning),
                    )
                    .child(
                        div()
                            .flex_shrink_0()
                            .font_semibold()
                            .child(action_label(&action.kind)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .truncate()
                            .text_color(muted)
                            .child(action.summary.clone()),
                    ),
            )
            .when_some(detail, |card, detail| {
                card.child(
                    div()
                        .id("approval-detail")
                        .w_full()
                        .max_h(px(240.))
                        .overflow_y_scroll()
                        .child(detail.h_auto()),
                )
            })
            .child(
                h_flex()
                    .flex_shrink_0()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .text_xs()
                            .text_color(muted)
                            .child(if plan {
                                "输入框里的文字会作为修改意见随“继续规划”发出"
                            } else {
                                "拒绝时输入框里的文字会作为理由发给 agent"
                            }),
                    )
                    .child(
                        Button::new("deny-action")
                            .small()
                            .outline()
                            .label(if plan { "继续规划" } else { "拒绝" })
                            .on_click(cx.listener(|shell, _, window, cx| {
                                shell.decide(false, false, window, cx)
                            })),
                    )
                    .when(can_persist, |row| {
                        row.child(
                            Button::new("always-allow-action")
                                .small()
                                .outline()
                                .label("总是允许")
                                .on_click(cx.listener(|shell, _, window, cx| {
                                    shell.decide(true, true, window, cx)
                                })),
                        )
                    })
                    .child(
                        Button::new("approve-action")
                            .small()
                            .primary()
                            .label(if plan { "开始执行" } else { "允许" })
                            .on_click(cx.listener(|shell, _, window, cx| {
                                shell.decide(true, false, window, cx)
                            })),
                    ),
            )
            .into_any_element()
    }
}

impl Shell {
    /// 提问卡：和 Claude Code TUI 一样一题一页，顶部 tab 切换，多题时最后一页汇总提交。
    fn render_questions(
        &self,
        session: &Session,
        action: &ActionRequest,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let questions = action.questions.clone().unwrap_or_default();
        let live = self.live.iter().find(|live| session.is(&live.key));
        let revision = live.map_or(0, |live| live.question_revision);
        let saved_texts = live
            .map(|live| live.other_texts.as_slice())
            .unwrap_or_default();
        let other_inputs: Vec<Entity<InputState>> = (0..questions.len())
            .map(|ix| {
                let key = session.key();
                let request_id = action.request_id.clone();
                let shell = cx.entity().downgrade();
                let text = saved_texts.get(ix).cloned().unwrap_or_default();
                window.use_keyed_state(
                    SharedString::from(format!(
                        "question-other-{key:?}-{request_id}-{revision}-{ix}"
                    )),
                    cx,
                    |window, cx| {
                        let mut input =
                            InputState::new(window, cx).placeholder("输入你的答案，Enter 确认");
                        input.set_value(text, window, cx);
                        cx.subscribe_in(
                            &cx.entity(),
                            window,
                            move |input, _, event: &InputEvent, window, cx| match event {
                                InputEvent::Change => {
                                    let text = input.value().to_string();
                                    let _ = shell.update(cx, |shell, _| {
                                        if let Some(live) =
                                            shell.live.iter_mut().find(|live| live.key == key)
                                        {
                                            live.set_other_text(&request_id, revision, ix, text);
                                        }
                                    });
                                }
                                InputEvent::PressEnter { .. } => {
                                    let _ = shell
                                        .update(cx, |shell, cx| shell.finish_other(window, cx));
                                }
                                _ => {}
                            },
                        )
                        .detach();
                        input
                    },
                )
            })
            .collect();
        // 新的提问自动聚焦卡片一次；选了“其他”时聚焦它的输入框。
        let focus_key = (action.request_id.clone(), revision);
        if self.question_focused.as_ref() != Some(&focus_key) {
            cx.defer_in(window, move |shell, window, cx| {
                window.focus(&shell.question_focus);
                shell.question_scroll.scroll_to_top_of_item(0);
                shell.question_focused = Some(focus_key);
                cx.notify();
            });
        }
        if let Some(input) = self
            .focus_other
            .and_then(|ix| other_inputs.get(ix).cloned())
        {
            if let Some(question) = self.focus_other.and_then(|ix| questions.get(ix)) {
                self.question_scroll
                    .scroll_to_item(question.options.len() + 2);
            }
            cx.defer_in(window, move |shell, window, cx| {
                input.update(cx, |input, cx| input.focus(window, cx));
                shell.focus_other = None;
            });
        }
        let picks = live.map(|live| live.picks.clone()).unwrap_or_default();
        let others = live.map(|live| live.others.clone()).unwrap_or_default();
        let tab = live.map_or(0, |live| live.question_tab);
        let cursor = live.map_or(0, |live| live.question_cursor);
        let tab_count = live.map_or(questions.len(), LiveSession::tab_count);
        let summary = live.is_some_and(LiveSession::on_summary_tab);
        let answers: Vec<Option<String>> = (0..questions.len())
            .map(|ix| live.and_then(|live| live.answer_text(ix)))
            .collect();
        let all_answered = answers.iter().all(Option::is_some);
        let theme = cx.theme();
        let (warning, muted, primary, danger, hover, border) = (
            theme.warning,
            theme.muted_foreground,
            theme.primary,
            theme.danger,
            theme.secondary,
            theme.border,
        );
        let tab_label = |ix: usize, question: &agentdeck_protocol::UserQuestion| {
            question
                .header
                .clone()
                .unwrap_or_else(|| format!("问题 {}", ix + 1))
        };

        let tabs = (tab_count > 1).then(|| {
            let last = questions.len();
            h_flex()
                .gap_1()
                .flex_wrap()
                .children(questions.iter().enumerate().map(|(ix, question)| {
                    let mark = if answers[ix].is_some() { "✓ " } else { "" };
                    Button::new(SharedString::from(format!("question-tab-{ix}")))
                        .small()
                        .ghost()
                        .selected(tab == ix)
                        .label(format!("{mark}{}", tab_label(ix, question)))
                        .on_click(cx.listener(move |shell, _, window, cx| {
                            shell.question_tab(ix, window, cx)
                        }))
                }))
                .child(
                    Button::new("question-tab-submit")
                        .small()
                        .ghost()
                        .selected(summary)
                        .label("提交")
                        .on_click(cx.listener(move |shell, _, window, cx| {
                            shell.question_tab(last, window, cx)
                        })),
                )
        });

        let body =
            if summary {
                v_flex()
                    .id("question-page")
                    .w_full()
                    .max_h(px(320.))
                    .overflow_y_scroll()
                    .track_scroll(&self.question_scroll)
                    .gap_1()
                    .children(questions.iter().enumerate().map(|(ix, question)| {
                        h_flex()
                            .id(SharedString::from(format!("question-summary-{ix}")))
                            .gap_2()
                            .px_2()
                            .border_1()
                            .border_color(gpui::transparent_black())
                            .py_1p5()
                            .rounded_md()
                            .items_center()
                            .text_sm()
                            .cursor_pointer()
                            .hover(|row| row.bg(hover))
                            .child(meta_chip(cx).flex_shrink_0().child(tab_label(ix, question)))
                            .child(
                                div()
                                    .flex_1()
                                    .min_w(px(0.))
                                    .truncate()
                                    .text_color(muted)
                                    .child(question.question.clone()),
                            )
                            .child(match &answers[ix] {
                                Some(answer) => div().flex_shrink_0().child(answer.clone()),
                                None => div().flex_shrink_0().text_color(danger).child("未回答"),
                            })
                            .on_click(cx.listener(move |shell, _, window, cx| {
                                shell.question_tab(ix, window, cx)
                            }))
                    }))
                    .into_any_element()
            } else {
                let question = questions.get(tab).cloned();
                let chosen = picks.get(tab).cloned().unwrap_or_default();
                let other_on = others.get(tab).copied().unwrap_or(false);
                let multi = question.as_ref().is_some_and(|q| q.multi_select);
                let option_row = |index: usize,
                                  label: String,
                                  description: Option<String>,
                                  selected: bool,
                                  choice: Option<String>| {
                    let marker = match (multi, selected) {
                        (true, true) => "☑",
                        (true, false) => "☐",
                        (false, true) => "●",
                        (false, false) => "○",
                    };
                    h_flex()
                        .id(SharedString::from(format!("question-{tab}-option-{index}")))
                        .w_full()
                        .gap_2()
                        .px_2()
                        .py_1p5()
                        .rounded_md()
                        .border_1()
                        .border_color(if selected {
                            primary
                        } else {
                            gpui::transparent_black()
                        })
                        .when(cursor == index, |row| row.bg(hover))
                        .cursor_pointer()
                        .hover(|row| row.bg(hover))
                        // 序号和标记贴着标题首行，说明再长也不往中间漂。
                        .items_start()
                        .text_sm()
                        .child(
                            h_flex()
                                .w(px(OPTION_INDEX_WIDTH))
                                .h(px(OPTION_LINE_HEIGHT))
                                .flex_shrink_0()
                                .items_center()
                                .text_color(muted)
                                .child(format!("{}", index + 1)),
                        )
                        .child(
                            h_flex()
                                .w(px(OPTION_MARKER_WIDTH))
                                .h(px(OPTION_LINE_HEIGHT))
                                .flex_shrink_0()
                                .items_center()
                                .justify_center()
                                .text_color(if selected { primary } else { muted })
                                .child(marker),
                        )
                        .child(
                            v_flex()
                                .flex_1()
                                .min_w(px(0.))
                                .child(
                                    div()
                                        .line_height(px(OPTION_LINE_HEIGHT))
                                        .when(selected, |d| d.font_semibold())
                                        .child(label),
                                )
                                .when_some(description, |col, description| {
                                    col.child(div().text_xs().text_color(muted).child(description))
                                }),
                        )
                        .on_click(cx.listener(move |shell, _, _, cx| {
                            shell.pick_option(tab, choice.clone(), cx)
                        }))
                };
                v_flex()
                    .id("question-page")
                    .w_full()
                    .max_h(px(320.))
                    .overflow_y_scroll()
                    .track_scroll(&self.question_scroll)
                    .gap_1()
                    .when_some(question, |page, question| {
                        let option_count = question.options.len();
                        page.child(
                            h_flex()
                                // 与选项行的边框 + 内边距对齐，题目文字和序号列齐平。
                                .px(px(OPTION_ROW_INSET))
                                .gap_2()
                                .items_center()
                                .text_sm()
                                .font_semibold()
                                .child(question.question.clone())
                                .when(multi, |row| {
                                    row.child(
                                        div()
                                            .text_xs()
                                            .font_normal()
                                            .text_color(muted)
                                            .child("可多选"),
                                    )
                                }),
                        )
                        .children(question.options.into_iter().enumerate().map(
                            |(index, option)| {
                                let selected = chosen.contains(&option.label);
                                option_row(
                                    index,
                                    option.label.clone(),
                                    option.description,
                                    selected,
                                    Some(option.label),
                                )
                            },
                        ))
                        .child(option_row(
                            option_count,
                            "其他".into(),
                            Some("自己输入答案".into()),
                            other_on,
                            None,
                        ))
                        .when_some(
                            other_inputs.get(tab).filter(|_| other_on).cloned(),
                            |page, input| {
                                page.child(
                                    div().w_full().pl(px(OPTION_TEXT_INSET)).child(
                                        div()
                                            .w_full()
                                            .px_2()
                                            .rounded_md()
                                            .border_1()
                                            .border_color(border)
                                            .bg(hover)
                                            .child(Input::new(&input).appearance(false)),
                                    ),
                                )
                            },
                        )
                    })
                    .into_any_element()
            };

        let primary_button =
            if summary || tab_count == 1 {
                Button::new("submit-answers")
                    .small()
                    .primary()
                    .label("提交回答")
                    .disabled(!all_answered)
                    .on_click(cx.listener(|shell, _, _, cx| shell.submit_answers(cx)))
            } else {
                Button::new("next-question")
                    .small()
                    .primary()
                    .label("下一题")
                    .on_click(cx.listener(move |shell, _, window, cx| {
                        shell.question_tab(tab + 1, window, cx)
                    }))
            };

        v_flex()
            .id("question-card")
            .track_focus(&self.question_focus)
            .when(self.question_focus.is_focused(window), |card| {
                card.key_context("QuestionCard")
            })
            .on_action(cx.listener(|shell, _: &NextQuestion, window, cx| {
                if let Some((live, _, _)) = shell.current_live() {
                    let tab = live.question_tab + 1;
                    shell.question_tab(tab, window, cx);
                }
            }))
            .on_action(cx.listener(|shell, _: &PreviousQuestion, window, cx| {
                if let Some((live, _, _)) = shell.current_live() {
                    let tab = live.question_tab.saturating_sub(1);
                    shell.question_tab(tab, window, cx);
                }
            }))
            .on_key_down(
                cx.listener(|shell, event: &gpui::KeyDownEvent, window, cx| {
                    shell.question_key(event, window, cx)
                }),
            )
            .w_full()
            .max_w(px(760.))
            .gap_2()
            .px_3()
            .py_2()
            .rounded_lg()
            .border_1()
            .border_color(warning.opacity(0.5))
            .bg(warning.opacity(0.08))
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .text_sm()
                    .child(
                        Icon::empty()
                            .xsmall()
                            .path(crate::ALERT_ICON)
                            .text_color(warning),
                    )
                    .child(div().flex_shrink_0().font_semibold().child("回答问题"))
                    .children(tabs),
            )
            .child(body)
            .child(
                h_flex()
                    .flex_shrink_0()
                    .gap_2()
                    .items_center()
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .text_xs()
                            .text_color(muted)
                            .child(if tab_count > 1 {
                                "←→ 或 Tab 切换 · ↑↓ 选择 · Enter 选中 · 数字键直选"
                            } else {
                                "↑↓ 选择 · Enter 选中 · 数字键直选"
                            }),
                    )
                    .child(
                        Button::new("skip-questions")
                            .small()
                            .outline()
                            .label("跳过")
                            .on_click(cx.listener(|shell, _, window, cx| {
                                shell.decide(false, false, window, cx)
                            })),
                    )
                    .child(primary_button),
            )
            .into_any_element()
    }
}

/// 提问卡选项行的列宽：序号列、标记列和标题行高，“其他”输入框按同一组数对齐文字列。
const OPTION_LINE_HEIGHT: f32 = 20.;
const OPTION_INDEX_WIDTH: f32 = 16.;
const OPTION_MARKER_WIDTH: f32 = 16.;
/// 选项行边框(1) + 内边距 px_2(8)。
const OPTION_ROW_INSET: f32 = 1. + 8.;
/// 行内缩进 + 序号列 + gap_2(8) + 标记列 + gap_2(8)。
const OPTION_TEXT_INSET: f32 =
    OPTION_ROW_INSET + OPTION_INDEX_WIDTH + 8. + OPTION_MARKER_WIDTH + 8.;

fn action_label(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::ExecuteCommand => "执行命令",
        ActionKind::EditFiles => "编辑文件",
        ActionKind::GrantExtraPermission => "使用工具",
        ActionKind::ApprovePlan => "批准计划",
        ActionKind::AnswerQuestions => "回答问题",
    }
}

fn mode_label(mode: ClaudeCodePermissionMode) -> &'static str {
    match mode {
        ClaudeCodePermissionMode::Default => "默认",
        ClaudeCodePermissionMode::AcceptEdits => "接受编辑",
        ClaudeCodePermissionMode::Plan => "计划",
        ClaudeCodePermissionMode::Auto => "自动",
        ClaudeCodePermissionMode::DontAsk => "不询问",
        ClaudeCodePermissionMode::BypassPermissions => "跳过权限",
    }
}

fn mode_menu_label(mode: ClaudeCodePermissionMode) -> &'static str {
    match mode {
        ClaudeCodePermissionMode::Default => "默认 · 逐项询问",
        ClaudeCodePermissionMode::AcceptEdits => "接受编辑 · 文件改动不再询问",
        ClaudeCodePermissionMode::Plan => "计划 · 只规划，批准后执行",
        ClaudeCodePermissionMode::Auto => "自动 · 由模型判断是否需要询问",
        ClaudeCodePermissionMode::DontAsk => "不询问 · 未预授权的工具一律拒绝",
        ClaudeCodePermissionMode::BypassPermissions => "跳过权限 · 全部放行（危险）",
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

/// 空态提示胶囊：状态点 + 文案，常驻但不抢视线。
fn read_only_notice(cx: &App) -> impl IntoElement + use<> {
    h_flex()
        .gap_2()
        .px_3()
        .py_1()
        .items_center()
        .rounded_full()
        .border_1()
        .border_color(cx.theme().border)
        .bg(cx.theme().muted.opacity(0.6))
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .child(div().size(px(6.)).rounded_full().bg(cx.theme().success))
        .child("点击卡片上的 + 新建会话，或在侧栏打开已有会话")
}

/// 会话头部的元信息标签。
fn meta_chip(cx: &App) -> gpui::Div {
    h_flex()
        .gap_1p5()
        .items_center()
        .px_2()
        .py_0p5()
        .rounded_md()
        .bg(cx.theme().muted)
        .border_1()
        .border_color(cx.theme().border)
        .text_xs()
        .text_color(cx.theme().muted_foreground)
}

/// 标题上方的小号强调行。
fn eyebrow(text: String, cx: &App) -> impl IntoElement + use<> {
    div()
        .px_3()
        .py_0p5()
        .rounded_full()
        .bg(cx.theme().primary.opacity(0.1))
        .text_xs()
        .font_medium()
        .text_color(cx.theme().primary)
        .child(text)
}

/// 主页 agent 卡片：点击只看该机器上该 agent 的会话，再点取消。
/// 多台机器时右上角带机器名标签。
#[allow(clippy::too_many_arguments)]
fn connector_card(
    (host, kind): (Host, AgentKind),
    show_machine: bool,
    loaded: usize,
    note: Option<String>,
    failed: bool,
    selected: bool,
    can_start: bool,
    cx: &mut Context<Shell>,
) -> impl IntoElement + use<> {
    let theme = cx.theme();
    let (accent, border, muted) = (theme.primary, theme.border, theme.muted);
    let surface: gpui::Hsla = theme.secondary;
    let machine = machine_label(&host);
    v_flex()
        .id(SharedString::from(format!(
            "agent-card-{}-{}",
            machine,
            kind.as_str()
        )))
        .w_full()
        .min_w(px(0.))
        .gap_4()
        .p_5()
        .rounded(px(14.))
        .bg(gpui::linear_gradient(
            180.,
            gpui::linear_color_stop(
                if selected {
                    accent.opacity(0.12)
                } else {
                    surface
                },
                0.,
            ),
            gpui::linear_color_stop(muted, 1.),
        ))
        .border_1()
        .border_color(if selected {
            accent.opacity(0.7)
        } else {
            border
        })
        .shadow_md()
        .cursor_pointer()
        .hover(move |style| {
            style.border_color(if selected {
                accent
            } else {
                border.lighten(0.6)
            })
        })
        .on_click({
            let host = host.clone();
            cx.listener(move |shell, _, _, cx| shell.toggle_agent_filter(host.clone(), kind, cx))
        })
        .child(
            h_flex()
                .justify_between()
                .items_center()
                .child(
                    div()
                        .size(px(32.))
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .justify_center()
                        .rounded(px(9.))
                        .bg(gpui::white().opacity(0.05))
                        .border_1()
                        .border_color(gpui::white().opacity(0.06))
                        .child(sidebar::agent_icon(kind, false)),
                )
                .child(
                    h_flex()
                        .min_w(px(0.))
                        .gap_1()
                        .items_center()
                        .when(show_machine, |row| {
                            row.child(
                                div()
                                    .min_w(px(0.))
                                    .px_2()
                                    .py_0p5()
                                    .rounded_full()
                                    .border_1()
                                    .border_color(border)
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .truncate()
                                    .child(machine.clone()),
                            )
                        })
                        .child(
                            Button::new(SharedString::from(format!(
                                "new-session-{}-{}",
                                machine,
                                kind.as_str()
                            )))
                            .ghost()
                            .xsmall()
                            .icon(Icon::empty().path(crate::PLUS_ICON))
                            .tooltip("在这里新建会话")
                            .disabled(!can_start)
                            .on_click(cx.listener(
                                move |shell, _, window, cx| {
                                    // 卡片本身的点击是筛选，这里不往上传。
                                    cx.stop_propagation();
                                    shell.start_draft(host.clone(), kind, window, cx);
                                },
                            )),
                        ),
                ),
        )
        .child(
            v_flex()
                .gap_1()
                .child(div().text_sm().font_semibold().child(agent_label(kind)))
                .child(
                    h_flex()
                        .gap_1p5()
                        .items_baseline()
                        .child(
                            div()
                                .text_size(px(28.))
                                .line_height(px(32.))
                                .font_semibold()
                                // 空来源降一档，视线先落到有内容的卡片上。
                                .when(loaded == 0, |n| n.text_color(cx.theme().muted_foreground))
                                .child(loaded.to_string()),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(cx.theme().muted_foreground)
                                .child(if selected {
                                    "个会话 · 已筛选"
                                } else {
                                    "个会话"
                                }),
                        ),
                )
                .when_some(note, |col, note| {
                    col.child(
                        div()
                            .text_xs()
                            .text_color(if failed {
                                cx.theme().danger
                            } else {
                                cx.theme().muted_foreground
                            })
                            .child(note),
                    )
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
                draft,
            } => self
                .render_session(session, transcript, list, *read_id, *draft, window, cx)
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
    use super::{middle_ellipsis, parent_hint, recent_projects};
    use crate::daemon;
    use agentdeck_protocol::{AgentKind, HistoryListItem, HistoryWarning, ThreadId};
    use gpui::{ScrollStrategy, UniformListScrollHandle};
    use std::path::{Path, PathBuf};

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
            draft: false,
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
        assert_eq!(local_time(u64::MAX), None);
        let (day, year, month, date, hour, minute) = local_time(1_700_000_000_000).unwrap();
        assert!((19_675..=19_676).contains(&day));
        assert_eq!(year, 2023);
        assert_eq!(month, 11);
        assert!((14..=15).contains(&date));
        assert!((0..24).contains(&hour));
        assert!((0..60).contains(&minute));
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
            draft: false,
        };
        assert!(!stage.finish_read(1, Ok((vec![], vec![warning()]))));

        stage = Stage::Session {
            session: local(first),
            transcript: Transcript::Loading,
            list: transcript_list(),
            read_id: 3,
            draft: false,
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
            Stage::Session { transcript: Transcript::Ready { blocks, warnings, .. }, list, .. }
                if blocks.len() == 1 && list.item_count() == 1 && warnings == &[warning()]
        ));

        if let Stage::Session {
            read_id,
            draft: false,
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
    fn cli_operation_waits_for_version_then_selects_install_or_update() {
        let mut agent = AgentHistory::new(AgentKind::Codex);
        assert_eq!(agent.next_operation(), None);
        for version in ["unknown", "codex unknown", "claude-code unknown"] {
            agent.version = Some(version.into());
            assert_eq!(agent.next_operation(), Some(super::AgentOperation::Install));
        }
        for version in ["codex-cli 0.158.0", "2.1.285 (Claude Code)"] {
            agent.version = Some(version.into());
            assert_eq!(agent.next_operation(), Some(super::AgentOperation::Update));
        }
    }

    #[test]
    fn failed_daemon_check_preserves_the_last_successful_version() {
        let mut machine = Machine::new(1, None);
        machine.daemon_checking = true;
        machine.complete_daemon_check(Err("timeout".into()));
        assert!(!machine.daemon_checking);
        assert_eq!(machine.daemon_version.as_deref(), Some("unknown"));
        assert_eq!(machine.daemon_protocol, None);

        machine.complete_daemon_check(Ok(("999.0.0".into(), 999)));
        machine.daemon_checking = true;
        machine.complete_daemon_check(Err("timeout".into()));
        assert!(!machine.daemon_checking);
        assert_eq!(machine.daemon_version.as_deref(), Some("999.0.0"));
        assert_eq!(machine.daemon_protocol, Some(999));
        assert_eq!(machine.daemon_check_error.as_deref(), Some("timeout"));

        machine.complete_daemon_check(Ok(("999.0.1".into(), 999)));
        assert_eq!(machine.daemon_version.as_deref(), Some("999.0.1"));
        assert!(machine.daemon_check_error.is_none());
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
        machine.daemon_checking = true;
        assert!(!machine.can_update_agents());
        machine.daemon_checking = false;
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
    fn refresh_waits_until_machine_requests_and_installs_finish() {
        let mut machines = vec![Machine::new(1, None)];
        assert!(super::sessions_refresh_ready(0, &machines));

        machines[0].connecting = true;
        assert!(!super::sessions_refresh_ready(0, &machines));
        machines[0].connecting = false;
        machines[0].installing = true;
        assert!(!super::sessions_refresh_ready(0, &machines));
        machines[0].installing = false;
        machines[0].agents.push(AgentHistory::new(AgentKind::Codex));
        machines[0].agents[0].operation = Some(super::AgentOperation::Update);
        assert!(!super::sessions_refresh_ready(0, &machines));
        assert!(!super::sessions_refresh_ready(1, &machines));
    }

    #[test]
    fn refresh_keeps_loaded_count_until_new_history_succeeds() {
        let mut machine = Machine::new(1, None);
        machine.prepare_agents(&[AgentKind::Codex]);
        machine.agents[0].complete(&mut Ok((vec![item(None); 51], vec![])));
        assert!(machine.agents[0].load_more());
        machine.agents[0].complete(&mut Ok((vec![item(None); 100], vec![])));

        machine.prepare_agents(&[AgentKind::ClaudeCode, AgentKind::Codex]);
        assert_eq!(machine.agents[0].status(), "读取中…");
        let source = &mut machine.agents[1];
        assert_eq!(source.status(), "已加载 100 · 加载中…");
        assert_eq!(source.request_limit(), 51);
        source.complete(&mut Err("timeout".into()));
        assert_eq!(source.status(), "已加载 100 · 加载失败");
        assert!(source.retry());
        source.complete(&mut Ok((vec![item(None); 12], vec![])));
        assert_eq!(source.status(), "已加载 12 个会话");

        machine.prepare_agents(&[AgentKind::Codex]);
        assert_eq!(machine.agents.len(), 1);
        assert_eq!(machine.agents[0].status(), "已加载 12 · 加载中…");
    }

    #[test]
    fn history_refresh_keeps_active_sessions_until_listed_or_closed() {
        use agentdeck_protocol::SessionId;

        let new_session = local(item(Some("本地首条消息")));
        let mut history_item = item(Some("已有历史"));
        history_item.thread_id = ThreadId("history".into());
        let mut stale_item = item(Some("已移除的历史"));
        stale_item.thread_id = ThreadId("stale".into());
        let mut other_agent = new_session.clone();
        other_agent.item.agent_kind = AgentKind::Codex;
        let mut sessions = vec![
            new_session.clone(),
            local(stale_item),
            remote(new_session.item.clone()),
            other_agent,
        ];
        let mut active = crate::live::LiveSession::new(new_session.key());
        active.session_id = Some(SessionId("active".into()));
        let mut live = vec![active];

        let loaded = super::replace_source_sessions(
            &mut sessions,
            &live,
            &None,
            AgentKind::ClaudeCode,
            vec![history_item.clone()],
        );
        assert_eq!(loaded, 2, "来源计数包含尚未出现在历史中的活动会话");
        assert_eq!(sessions.len(), 4, "不影响其他机器或 agent 的同名 thread");
        assert!(
            sessions
                .iter()
                .any(|session| session.is(&new_session.key()))
        );
        assert!(
            !sessions
                .iter()
                .any(|session| session.item.thread_id.0 == "stale")
        );

        let mut listed_new = new_session.item.clone();
        listed_new.title = Some("历史更新后的标题".into());
        let loaded = super::replace_source_sessions(
            &mut sessions,
            &live,
            &None,
            AgentKind::ClaudeCode,
            vec![history_item.clone(), listed_new.clone(), listed_new],
        );
        assert_eq!(loaded, 2, "历史条目与本地条目按完整身份去重");
        assert_eq!(
            sessions
                .iter()
                .find(|session| session.is(&new_session.key()))
                .unwrap()
                .item
                .title
                .as_deref(),
            Some("历史更新后的标题"),
        );

        live[0].disconnected("连接已关闭");
        let loaded = super::replace_source_sessions(
            &mut sessions,
            &live,
            &None,
            AgentKind::ClaudeCode,
            vec![history_item],
        );
        assert_eq!(loaded, 1);
        assert_eq!(sessions.len(), 3);
        assert!(
            !sessions
                .iter()
                .any(|session| session.is(&new_session.key()))
        );
    }

    #[test]
    fn history_limit_hint_survives_extra_active_sessions() {
        let mut source = AgentHistory::new(AgentKind::ClaudeCode);
        source.limit = super::MAX_HISTORY_LIST_LIMIT;
        source.complete(&mut Ok((
            vec![item(None); super::MAX_HISTORY_LIST_LIMIT],
            vec![],
        )));
        source.loaded += 1;

        assert_eq!(source.list_hint(), Some("已达 2,000 条上限"));
        assert!(!source.can_load_more());
    }

    #[test]
    fn refresh_drops_sessions_for_agents_removed_from_a_machine() {
        let mut removed = item(None);
        removed.agent_kind = AgentKind::Codex;
        let mut sessions = vec![local(item(None)), local(removed), remote(item(None))];

        super::retain_active_machine_sessions(&mut sessions, &None, &[AgentKind::ClaudeCode]);

        assert_eq!(sessions.len(), 2);
        assert!(sessions[0].host.is_none());
        assert!(sessions[1].host.is_some());
        assert!(
            sessions
                .iter()
                .all(|session| session.item.agent_kind == AgentKind::ClaudeCode)
        );
    }

    #[test]
    fn session_title_falls_back_to_the_thread_id_and_keeps_one_line() {
        assert_eq!(session_title(&item(None)), "7330efa6");
        assert_eq!(session_title(&item(Some("   "))), "7330efa6");
        assert_eq!(session_title(&item(Some("第一行\n第二行"))), "第一行");
    }

    #[test]
    fn recent_projects_are_per_host_newest_first_and_deduped() {
        let at = |cwd: &str, ms| HistoryListItem {
            cwd: cwd.into(),
            last_active_ms: ms,
            ..item(None)
        };
        let sessions = [
            local(at("/a", 1)),
            local(at("/b", 3)),
            local(at("/a", 2)),
            local(at("", 9)),
            remote(at("/r", 5)),
        ];
        let paths = |v: Vec<PathBuf>| {
            v.into_iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(paths(recent_projects(&sessions, &None, 8)), ["/b", "/a"]);
        assert_eq!(paths(recent_projects(&sessions, &None, 1)), ["/b"]);
        assert_eq!(
            paths(recent_projects(&sessions, &sessions[4].host, 8)),
            ["/r"]
        );
    }

    #[test]
    fn middle_ellipsis_keeps_head_and_tail() {
        assert_eq!(middle_ellipsis("AgentDeck", 20), "AgentDeck");
        let short = middle_ellipsis("accounts-backup-20260713-152226", 20);
        assert_eq!(short, "accounts-b…13-152226");
        assert_eq!(short.chars().count(), 20);
    }

    #[test]
    fn parent_hint_abbreviates_home() {
        let home = Some(Path::new("/Users/dev"));
        assert_eq!(
            parent_hint(Path::new("/Users/dev/Documents/x"), home),
            "~/Documents"
        );
        assert_eq!(parent_hint(Path::new("/Users/dev/x"), home), "~");
        assert_eq!(parent_hint(Path::new("/srv/x"), home), "/srv");
        assert_eq!(parent_hint(Path::new("/srv/x"), None), "/srv");
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
