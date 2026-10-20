//! APK Info GUI — apk-info 的 Windows 图形界面（免安装单文件版）
//!
//! 单个 exe 两种用法：
//!   - 无参数启动        -> 打开图形窗口（支持拖放 APK 自动解析、分类展示结果）
//!   - 带 CLI 子命令     -> 与原版 apk-info 命令行完全一致
//!        (show / extract / axml / repack / completion)
//!
//! GUI 内部通过"调用自身 exe 的 CLI 模式"执行全部功能，
//! 因此图形界面与命令行功能 100% 对齐，无需任何外部依赖。

// Windows GUI 子系统：双击不弹出黑色控制台窗口；
// 从 cmd/PowerShell 运行时 stdout/stderr 输出依然正常。
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui;
use egui::RichText;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{Shell, generate};

/// 与 cli crate 一致的命令行结构（保持命令行兼容）
/// 注意：不使用 arg_required_else_help，无子命令时进入 GUI 窗口。
#[derive(Parser)]
#[command(name = "apk-info-gui", version, about)]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 显示 APK 基本信息
    Show {
        /// 一个或多个 APK 文件路径
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// 显示签名信息
        #[arg(short, long)]
        sigs: bool,
        /// 以 JSON 格式输出
        #[arg(short, long)]
        json: bool,
    },
    /// 以 zip 方式解包 APK
    Extract {
        /// 一个或多个 APK 文件路径
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// 输出目录（默认 ./<文件名>.unp）
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// 只提取匹配正则的文件，可多次指定
        #[arg(short, long)]
        files: Vec<String>,
        /// 显示每个文件的提取进度
        #[arg(short, long)]
        verbose: bool,
        /// 以 apktool 风格解码资源（XML 与 resources.arsc）
        #[arg(short, long)]
        resources: bool,
        /// 仅列出压缩包内容而不解压
        #[arg(short, long)]
        list: bool,
    },
    /// 读取并美化打印 AndroidManifest.xml
    Axml {
        /// AndroidManifest.xml 或包含它的 APK 路径
        #[arg(required = true)]
        path: PathBuf,
    },
    /// 将 BadPack 损坏的 APK 重打包为标准 zip
    Repack {
        /// 一个或多个 APK 文件路径
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// 输出文件（与 -d 连用时必须是纯文件名）
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
        /// 输出目录（默认与源文件同目录）
        #[arg(short = 'd', long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
    /// 生成 shell 补全
    Completion {
        /// 目标 shell
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn main() {
    let cli = Cli::parse();

    // 无子命令 -> 启动图形界面
    if cli.commands.is_none() {
        if let Err(e) = run_gui() {
            eprintln!("GUI 启动失败: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    // 有子命令 -> 命令行模式（与原版 apk-info 等价）
    if let Err(e) = run_cli(&cli.commands.unwrap()) {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

fn run_cli(cmd: &Commands) -> anyhow::Result<()> {
    match cmd {
        Commands::Show { paths, sigs, json } => {
            apk_info_cli::commands::command_show(paths, sigs, json)
        }
        Commands::Extract {
            paths,
            output,
            files,
            verbose,
            resources,
            list,
        } => apk_info_cli::commands::command_extract(
            paths,
            output,
            files,
            *verbose,
            *resources,
            *list,
        ),
        Commands::Axml { path } => apk_info_cli::commands::command_axml(path),
        Commands::Repack {
            paths,
            output,
            output_dir,
        } => apk_info_cli::commands::command_repack(paths, output, output_dir),
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(*shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
//  分类输出数据模型（对应 cli 的 show --json 输出）
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct CertInfo {
    serial: String,
    subject: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
    signature_type: String,
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Default, Clone)]
struct SigGroup {
    /// 签名方案中文名，如 "APK 签名方案 v2"
    kind: String,
    certs: Vec<CertInfo>,
    /// 渠道值（ApkChannelBlock / VasDolly）
    channel: Option<String>,
    /// 十六进制数据（Packer NG v2）
    hex: Option<String>,
    /// 纯标记（Google Play Frosting 等）
    marker: Option<String>,
}

#[derive(Default, Clone)]
struct ShowResult {
    file: String,
    package_name: String,
    version_name: String,
    version_code: String,
    main_activity: String,
    min_sdk: String,
    max_sdk: String,
    target_sdk: String,
    label: String,
    abis: Vec<String>,
    sigs: Vec<SigGroup>,
    container_sigs: Vec<SigGroup>,
    raw_json: String,
    error: Option<String>,
}

impl ShowResult {
    fn from_json(v: &serde_json::Value) -> ShowResult {
        let s = |k: &str| -> String {
            v.get(k).and_then(|x| x.as_str()).unwrap_or("-").to_string()
        };
        let mut r = ShowResult {
            package_name: s("package_name"),
            version_name: s("version_name"),
            version_code: s("version_code"),
            main_activity: s("main_activity"),
            min_sdk: s("min_sdk_version"),
            max_sdk: s("max_sdk_version"),
            target_sdk: s("target_sdk_version"),
            label: s("application_label"),
            raw_json: v.to_string(),
            ..Default::default()
        };
        if let Some(abis) = v.get("abis").and_then(|x| x.as_array()) {
            r.abis = abis
                .iter()
                .filter_map(|a| a.as_str().map(|x| x.to_string()))
                .collect();
        }
        if let Some(sigs) = v.get("signatures").and_then(|x| x.as_array()) {
            r.sigs = sigs.iter().filter_map(parse_signature).collect();
        }
        if let Some(sigs) = v.get("container_signatures").and_then(|x| x.as_array()) {
            r.container_sigs = sigs.iter().filter_map(parse_signature).collect();
        }
        r
    }
}

/// 签名方案的中文名称
fn sig_kind_cn(tag: &str) -> String {
    match tag {
        "v1" => "APK 签名方案 v1 (JAR)".to_string(),
        "v2" => "APK 签名方案 v2".to_string(),
        "v3" => "APK 签名方案 v3".to_string(),
        "v31" => "APK 签名方案 v3.1".to_string(),
        "v4" => "APK 签名方案 v4".to_string(),
        "stamp_block_v1" => "源印章块 Stamp Block v1".to_string(),
        "stamp_block_v2" => "源印章块 Stamp Block v2".to_string(),
        "apk_channel_block" => "APK 渠道块 ApkChannelBlock".to_string(),
        "packer_next_gen_v2" => "加固信息 Packer NG v2".to_string(),
        "google_play_frosting" => "Google Play Frosting 元数据".to_string(),
        "vasdolly_v2" => "腾讯 VasDolly 渠道 v2".to_string(),
        "unknown" => "未知签名/信息块".to_string(),
        other => other.to_string(),
    }
}

/// 解析单个签名条目（serde 外部标签格式，可能为对象或字符串）
fn parse_signature(v: &serde_json::Value) -> Option<SigGroup> {
    match v {
        serde_json::Value::Object(map) => {
            for (tag, val) in map {
                let mut g = SigGroup {
                    kind: sig_kind_cn(tag),
                    ..Default::default()
                };
                match tag.as_str() {
                    "v1" | "v2" | "v3" | "v31" | "v4" => {
                        if let Some(arr) = val.as_array() {
                            g.certs = arr.iter().filter_map(parse_cert).collect();
                        }
                    }
                    "stamp_block_v1" | "stamp_block_v2" => {
                        if let Some(c) = parse_cert(val) {
                            g.certs.push(c);
                        }
                    }
                    "apk_channel_block" | "vasdolly_v2" => {
                        g.channel = val.as_str().map(|x| x.to_string());
                    }
                    "packer_next_gen_v2" => {
                        if let Some(arr) = val.as_array() {
                            let hex: Vec<String> = arr
                                .iter()
                                .filter_map(|b| b.as_u64().map(|n| format!("{n:02x}")))
                                .collect();
                            g.hex = Some(hex.join(""));
                        }
                    }
                    "google_play_frosting" | "unknown" => {
                        g.marker = Some(val.to_string());
                    }
                    _ => {}
                }
                return Some(g);
            }
            None
        }
        serde_json::Value::String(tag) => Some(SigGroup {
            kind: sig_kind_cn(tag),
            marker: Some("存在".to_string()),
            ..Default::default()
        }),
        _ => None,
    }
}

fn parse_cert(v: &serde_json::Value) -> Option<CertInfo> {
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("-").to_string();
    Some(CertInfo {
        serial: s("serial_number"),
        subject: s("subject"),
        issuer: s("issuer"),
        valid_from: s("valid_from"),
        valid_until: s("valid_until"),
        signature_type: s("signature_type"),
        md5: s("md5_fingerprint"),
        sha1: s("sha1_fingerprint"),
        sha256: s("sha256_fingerprint"),
    })
}

// ---------------------------------------------------------------------------
//  主题与通用控件
// ---------------------------------------------------------------------------

// 浅色主题配色：白底深字，最高对比度，Windows 下清晰易读
const BG_DEEP: egui::Color32 = egui::Color32::from_rgb(243, 245, 249);
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(255, 255, 255);
const BORDER: egui::Color32 = egui::Color32::from_rgb(208, 214, 224);
const TEXT_MAIN: egui::Color32 = egui::Color32::from_rgb(38, 42, 50);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(104, 112, 126);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(46, 111, 216);
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(64, 132, 240);
const GREEN: egui::Color32 = egui::Color32::from_rgb(42, 150, 92);
const GREEN_HOVER: egui::Color32 = egui::Color32::from_rgb(56, 180, 110);
const GREEN_TEXT: egui::Color32 = egui::Color32::from_rgb(26, 132, 78);
const BLUE: egui::Color32 = egui::Color32::from_rgb(52, 120, 210);
const ORANGE: egui::Color32 = egui::Color32::from_rgb(200, 132, 50);
const TEAL: egui::Color32 = egui::Color32::from_rgb(40, 145, 145);
const ERR: egui::Color32 = egui::Color32::from_rgb(200, 56, 56);

fn setup_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(17.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(18.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Heading,
        egui::FontId::new(23.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(15.0, egui::FontFamily::Monospace),
    );
    style.spacing.item_spacing = egui::vec2(14.0, 12.0);
    style.spacing.button_padding = egui::vec2(16.0, 10.0);
    style.spacing.interact_size.y = 42.0;

    let v = &mut style.visuals;
    v.dark_mode = false;
    v.panel_fill = BG_DEEP;
    v.window_fill = BG_DEEP;
    v.extreme_bg_color = BG_DEEP;
    v.faint_bg_color = BG_CARD;
    v.override_text_color = Some(TEXT_MAIN);
    v.selection.bg_fill = ACCENT;
    v.selection.stroke = egui::Stroke::NONE;
    v.hyperlink_color = egui::Color32::from_rgb(28, 110, 210);
    let cr = egui::Rounding::same(10.0);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.rounding = cr;
    }
    v.widgets.inactive.bg_fill = BG_INPUT;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, BORDER);
    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(238, 242, 249);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT_HOVER);
    v.widgets.active.bg_fill = ACCENT;
    v.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, ACCENT_HOVER);
    style.visuals.window_rounding = egui::Rounding::same(12.0);
    ctx.set_style(style);
}

/// 圆角卡片容器
fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::default()
        .fill(BG_CARD)
        .stroke(egui::Stroke::new(1.0_f32, BORDER))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(egui::Margin::same(16.0))
        .show(ui, add_contents);
}

/// 分类界面顶部标题（中文说明本界面输出什么）
fn section_heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("▍").size(26.0).color(ACCENT_HOVER));
        ui.label(RichText::new(text).heading().color(TEXT_MAIN));
    });
    ui.add_space(4.0);
    ui.separator();
}

/// 主操作按钮（大尺寸 + 强调色）
fn action_button(text: &str, color: egui::Color32, _hover: egui::Color32) -> egui::Button {
    egui::Button::new(RichText::new(text).size(18.0).color(egui::Color32::WHITE))
        .min_size(egui::vec2(160.0, 48.0))
        .fill(color)
        .stroke(egui::Stroke::new(1.0_f32, color))
        .rounding(egui::Rounding::same(10.0))
}

/// 次按钮（大尺寸）
fn ghost_button(text: &str) -> egui::Button {
    egui::Button::new(RichText::new(text).size(17.0))
        .min_size(egui::vec2(140.0, 46.0))
        .fill(BG_INPUT)
        .stroke(egui::Stroke::new(1.0_f32, BORDER))
        .rounding(egui::Rounding::same(10.0))
}

/// 中文标签 + 值 的信息行
fn field_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}：")).strong().size(16.0).color(TEXT_MAIN));
        ui.label(RichText::new(value).size(16.0).color(TEXT_DIM));
    });
}

/// 把基本信息的解析结果格式化为可复制文本
fn format_show_text(r: &ShowResult) -> String {
    if let Some(err) = &r.error {
        return format!("文件: {}\n错误: {err}\n", r.file);
    }
    let abis = if r.abis.is_empty() {
        "-".to_string()
    } else {
        r.abis.join(", ")
    };
    format!(
        "文件: {}\n应用包名: {}\n主 Activity: {}\n应用名称: {}\n版本名: {}\n版本号: {}\n最低 SDK: {}\n最高 SDK: {}\n目标 SDK: {}\nCPU 架构: {}\n",
        r.file,
        r.package_name,
        r.main_activity,
        r.label,
        r.version_name,
        r.version_code,
        r.min_sdk,
        r.max_sdk,
        r.target_sdk,
        abis
    )
}

/// 把签名结果格式化为可复制文本
fn format_sigs_text(r: &ShowResult) -> String {
    let mut s = format!("文件: {}\n", r.file);
    if r.sigs.is_empty() && r.container_sigs.is_empty() {
        s.push_str("无签名信息\n");
        return s;
    }
    s.push_str("APK 签名块:\n");
    for g in &r.sigs {
        s.push_str(&format!("  {}\n", g.kind));
        if let Some(c) = &g.channel {
            s.push_str(&format!("    渠道值: {c}\n"));
        }
        if let Some(h) = &g.hex {
            s.push_str(&format!("    数据值: {h}\n"));
        }
        if let Some(m) = &g.marker {
            s.push_str(&format!("    状态: {m}\n"));
        }
        for c in &g.certs {
            s.push_str(&format!(
                "    证书: 序列号 {} | Subject: {} | Issuer: {} | 有效期 {} ~ {} | 算法: {} | MD5: {} | SHA1: {} | SHA256: {}\n",
                c.serial, c.subject, c.issuer, c.valid_from, c.valid_until, c.signature_type, c.md5, c.sha1, c.sha256
            ));
        }
    }
    if !r.container_sigs.is_empty() {
        s.push_str("容器签名块:\n");
        for g in &r.container_sigs {
            s.push_str(&format!("  {}\n", g.kind));
            for c in &g.certs {
                s.push_str(&format!(
                    "    证书: 序列号 {} | Subject: {} | Issuer: {} | 有效期 {} ~ {} | 算法: {} | MD5: {} | SHA1: {} | SHA256: {}\n",
                    c.serial, c.subject, c.issuer, c.valid_from, c.valid_until, c.signature_type, c.md5, c.sha1, c.sha256
                ));
            }
        }
    }
    s
}

/// 把文本写入剪贴板
fn copy_to_clipboard(ui: &egui::Ui, text: &str) {
    ui.ctx().output_mut(|o| o.copied_text = text.to_string());
}

/// 证书信息块（中文标注）
fn cert_block(ui: &mut egui::Ui, c: &CertInfo) {
    egui::Grid::new(ui.next_auto_id())
        .num_columns(2)
        .spacing([18.0, 7.0])
        .show(ui, |ui| {
            ui.label(RichText::new("证书序列号").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.serial).size(15.0));
            ui.end_row();
            ui.label(RichText::new("主体 (Subject)").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.subject).size(15.0));
            ui.end_row();
            ui.label(RichText::new("签发者 (Issuer)").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.issuer).size(15.0));
            ui.end_row();
            ui.label(RichText::new("有效期开始").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.valid_from).size(15.0));
            ui.end_row();
            ui.label(RichText::new("有效期截止").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.valid_until).size(15.0));
            ui.end_row();
            ui.label(RichText::new("签名算法").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.signature_type).size(15.0));
            ui.end_row();
            ui.label(RichText::new("MD5 指纹").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.md5).size(15.0));
            ui.end_row();
            ui.label(RichText::new("SHA1 指纹").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.sha1).size(15.0));
            ui.end_row();
            ui.label(RichText::new("SHA256 指纹").color(TEXT_DIM).size(15.0));
            ui.label(RichText::new(&c.sha256).size(15.0));
            ui.end_row();
        });
}

// ---------------------------------------------------------------------------
//  GUI 部分
// ---------------------------------------------------------------------------

/// 当前正在执行的命令类型，用于将输出路由到对应分类界面
#[derive(Clone, Copy, PartialEq)]
enum CmdKind {
    Show,
    Axml,
    Extract,
    Repack,
}

enum Event {
    Line(CmdKind, String),
    Done(CmdKind, anyhow::Result<()>),
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Show,
    Sigs,
    Axml,
    Extract,
    Repack,
}

struct App {
    files: Vec<String>,
    path_input: String,
    tab: Tab,
    // axml
    axml_path: String,
    // extract
    extract_output: String,
    extract_filter: String,
    extract_verbose: bool,
    extract_resources: bool,
    extract_list: bool,
    // repack
    repack_output: String,
    repack_output_dir: String,
    // 分类输出
    show_results: Vec<ShowResult>,
    show_buf: String,
    manifest_text: String,
    extract_log: String,
    repack_log: String,
    // 运行状态
    status: String,
    running: bool,
    rx: Option<Receiver<Event>>,
    cmd_log: String,
    opened_env: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_theme(&cc.egui_ctx);
        Self {
            files: Vec::new(),
            path_input: String::new(),
            tab: Tab::Show,
            axml_path: String::new(),
            extract_output: String::new(),
            extract_filter: String::new(),
            extract_verbose: false,
            extract_resources: false,
            extract_list: false,
            repack_output: String::new(),
            repack_output_dir: String::new(),
            show_results: Vec::new(),
            show_buf: String::new(),
            manifest_text: String::new(),
            extract_log: String::new(),
            repack_log: String::new(),
            status: "就绪".to_string(),
            running: false,
            rx: None,
            cmd_log: String::new(),
            opened_env: false,
        }
    }

    /// 启动一个命令线程：调用自身 exe 的 CLI 模式
    fn launch(&mut self, args: &[String], kind: CmdKind) {
        if self.running {
            self.set_status_err("上一个任务仍在运行，请等待完成");
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                self.set_status_err(&format!("无法定位程序自身路径: {e}"));
                return;
            }
        };
        self.cmd_log = format!("{} {}", exe.display(), args.join(" "));
        self.running = true;
        self.status = "运行中…".to_string();

        let (tx, rx) = mpsc::channel::<Event>();
        self.rx = Some(rx);

        let owned_args: Vec<String> = args.iter().cloned().collect();
        thread::spawn(move || {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args(&owned_args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .env("NO_COLOR", "1")
                .env("CLICOLOR", "0");
            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(Event::Line(kind, format!("无法启动子进程: {e}")));
                    let _ = tx.send(Event::Done(kind, Err(anyhow::anyhow!(e.to_string()))));
                    return;
                }
            };
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let tx_out = tx.clone();
            let tx_err = tx.clone();
            if let Some(mut so) = stdout {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match std::io::Read::read(&mut so, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let s = String::from_utf8_lossy(&buf[..n]).to_string();
                                if tx_out.send(Event::Line(kind, s)).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            if let Some(mut se) = stderr {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match std::io::Read::read(&mut se, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let s = String::from_utf8_lossy(&buf[..n]).to_string();
                                if tx_err.send(Event::Line(kind, s)).is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            let status = child.wait();
            let _ = tx.send(Event::Done(
                kind,
                match status {
                    Ok(s) if s.success() => Ok(()),
                    Ok(s) => Err(anyhow::anyhow!("命令退出码: {}", s.code().unwrap_or(-1))),
                    Err(e) => Err(anyhow::anyhow!(e.to_string())),
                },
            ));
        });
    }

    fn set_status_err(&mut self, msg: &str) {
        self.status = format!("失败: {msg}");
        self.running = false;
        self.rx = None;
    }

    fn append_log(dst: &mut String, s: &str) {
        const MAX: usize = 4_000_000;
        if dst.len() > MAX {
            *dst = dst[dst.len() - MAX / 2..].to_string();
        }
        dst.push_str(s);
    }

    fn poll(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &self.rx {
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
        }
        if events.is_empty() {
            return;
        }
        for ev in events {
            match ev {
                Event::Line(kind, s) => match kind {
                    CmdKind::Show => Self::append_log(&mut self.show_buf, &s),
                    CmdKind::Axml => Self::append_log(&mut self.manifest_text, &s),
                    CmdKind::Extract => Self::append_log(&mut self.extract_log, &s),
                    CmdKind::Repack => Self::append_log(&mut self.repack_log, &s),
                },
                Event::Done(kind, res) => {
                    match res {
                        Ok(()) => self.status = "完成 ✓".to_string(),
                        Err(e) => {
                            self.status = format!("失败: {e}");
                        }
                    }
                    self.running = false;
                    if kind == CmdKind::Show {
                        self.finish_show();
                    }
                    self.rx = None;
                }
            }
        }
    }

    /// show 命令结束：把收集到的 JSON 输出解析为分类数据
    fn finish_show(&mut self) {
        let raw = std::mem::take(&mut self.show_buf);
        let mut results = Vec::new();
        let mut parse_error: Option<String> = None;
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(v) => results.push(ShowResult::from_json(&v)),
                Err(e) => {
                    parse_error = Some(format!("{line} （解析失败: {e}）"));
                }
            }
        }
        if !results.is_empty() {
            for (i, r) in results.iter_mut().enumerate() {
                if i < self.files.len() {
                    r.file = self.files[i].clone();
                }
            }
            self.show_results = results;
            self.status = format!("完成 ✓（已解析 {} 个文件）", self.show_results.len());
        }
        if let Some(err) = parse_error {
            let mut r = ShowResult {
                error: Some(err),
                ..Default::default()
            };
            r.file = self.files.first().cloned().unwrap_or_default();
            self.show_results.push(r);
        }
        if self.show_results.is_empty() {
            self.show_results.push(ShowResult {
                error: Some("未获得可解析的输出".to_string()),
                ..Default::default()
            });
        }
    }

    /// 打开一个文件路径：加入列表并自动解析
    fn open_path(&mut self, path: &str) {
        let p = path.trim();
        if p.is_empty() {
            return;
        }
        let path = std::path::Path::new(p);
        if path.is_file() {
            let s = path.display().to_string();
            if !self.files.contains(&s) {
                self.files.push(s);
            }
            self.analyze_current();
        } else {
            self.status = format!("路径不存在或不是文件: {p}");
        }
    }

    /// 对当前文件列表执行 show --sigs --json，并切到基本信息界面
    fn analyze_current(&mut self) {
        if self.files.is_empty() || self.running {
            return;
        }
        let mut args = vec!["show".to_string()];
        args.push("--sigs".to_string());
        args.push("--json".to_string());
        args.extend(self.files.iter().cloned());
        self.tab = Tab::Show;
        self.show_results.clear();
        self.show_buf.clear();
        self.launch(&args, CmdKind::Show);
    }

    fn pick_files(&mut self) {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter("Android 应用包", &["apk", "xapk", "apkm"])
            .add_filter("所有文件", &["*"])
            .pick_files()
        {
            for p in paths {
                let s = p.display().to_string();
                if !self.files.contains(&s) {
                    self.files.push(s);
                }
            }
            self.analyze_current();
        }
    }

    // ------------------------------------------------------------------
    //  各分类界面
    // ------------------------------------------------------------------

    /// 基本信息分类界面
    fn show_tab(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "📋 基本信息");
        if self.show_results.is_empty() && !self.running {
            ui.add_space(8.0);
            ui.label(
                RichText::new("还没有解析结果。请在上方输入路径、点击“浏览…”或将 APK 文件直接拖入本窗口。")
                    .size(17.0)
                    .color(TEXT_DIM),
            );
            return;
        }
        if self.show_results.is_empty() && self.running {
            ui.label(RichText::new("正在解析，请稍候…").color(TEXT_DIM));
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (idx, r) in self.show_results.iter().enumerate() {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("■ 文件 {}:", idx + 1)).strong().size(18.0));
                        ui.label(RichText::new(&r.file).color(TEXT_DIM));
                        if ui.add(ghost_button("📋 复制结果")).clicked() {
                            copy_to_clipboard(ui, &format_show_text(r));
                        }
                    });
                    ui.add_space(4.0);
                    if let Some(err) = &r.error {
                        ui.colored_label(ERR, err);
                    } else {
                        field_row(ui, "应用包名 (Package Name)", &r.package_name);
                        field_row(ui, "主 Activity (Main Activity)", &r.main_activity);
                        field_row(ui, "应用名称 (Application Label)", &r.label);
                        field_row(ui, "版本名 (Version Name)", &r.version_name);
                        field_row(ui, "版本号 (Version Code)", &r.version_code);
                        field_row(ui, "最低 SDK (Min SDK)", &r.min_sdk);
                        field_row(ui, "最高 SDK (Max SDK)", &r.max_sdk);
                        field_row(ui, "目标 SDK (Target SDK)", &r.target_sdk);
                        let abis = if r.abis.is_empty() {
                            "-".to_string()
                        } else {
                            r.abis.join(", ")
                        };
                        field_row(ui, "CPU 架构 (ABIs)", &abis);
                    }
                });
                ui.add_space(10.0);
            }
        });
    }

    /// 签名信息分类界面
    fn sigs_tab(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "🛡️ 签名信息");
        if self.show_results.is_empty() {
            ui.add_space(8.0);
            ui.label(
                RichText::new("暂无签名数据，请先解析 APK。").color(TEXT_DIM),
            );
            return;
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (idx, r) in self.show_results.iter().enumerate() {
                if r.error.is_some() {
                    continue;
                }
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("■ 文件 {}: {}", idx + 1, r.file))
                                .strong()
                                .size(18.0),
                        );
                        if ui.add(ghost_button("🛡️ 复制结果")).clicked() {
                            copy_to_clipboard(ui, &format_sigs_text(r));
                        }
                    });
                    ui.add_space(4.0);
                    ui.label(RichText::new("APK 签名块：").strong().size(17.0));
                    if r.sigs.is_empty() {
                        ui.label(RichText::new("  无签名信息").color(TEXT_DIM));
                    }
                    for g in &r.sigs {
                        ui.group(|ui| {
                            ui.label(RichText::new(format!("🔑 {}", g.kind)).strong().size(17.0));
                            if let Some(c) = &g.channel {
                                ui.label(RichText::new(format!("  渠道值: {c}")).size(16.0));
                            }
                            if let Some(h) = &g.hex {
                                ui.label(RichText::new(format!("  数据值: {h}")).monospace().size(14.0));
                            }
                            if let Some(m) = &g.marker {
                                ui.label(RichText::new(format!("  状态: {m}")).size(16.0));
                            }
                            for c in &g.certs {
                                ui.add_space(4.0);
                                cert_block(ui, c);
                            }
                        });
                        ui.add_space(6.0);
                    }
                    if !r.container_sigs.is_empty() {
                        ui.add_space(4.0);
                        ui.label(RichText::new("容器签名块：").strong().size(17.0));
                        for g in &r.container_sigs {
                            ui.group(|ui| {
                                ui.label(RichText::new(format!("🔑 {}", g.kind)).strong().size(17.0));
                                for c in &g.certs {
                                    ui.add_space(4.0);
                                    cert_block(ui, c);
                                }
                            });
                            ui.add_space(6.0);
                        }
                    }
                });
                ui.add_space(10.0);
            }
        });
    }

    /// AndroidManifest 分类界面（一键读取当前 APK + 手动路径直绑输入框）
    fn axml_tab(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "📄 AndroidManifest.xml");
        ui.add_space(4.0);

        // ① 一键读取当前已加载 APK 的清单
        let has_files = !self.files.is_empty();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    has_files && !self.running,
                    action_button("📄 读取该 APK 的 Manifest", TEAL, egui::Color32::from_rgb(64, 190, 190)),
                )
                .clicked()
            {
                if let Some(f) = self.files.first().cloned() {
                    self.run_axml(&f);
                }
            }
            if let Some(f) = self.files.first() {
                ui.label(RichText::new(format!("已加载：{f}")).size(15.0).color(TEXT_DIM));
            } else {
                ui.label(RichText::new("请先在顶部添加 APK 文件。").size(15.0).color(TEXT_DIM));
            }
        });
        ui.add_space(6.0);

        // ② 手动：指定 APK 或 .xml 路径
        ui.horizontal(|ui| {
            ui.label(RichText::new("指定路径：").strong().size(17.0));
            let w = ui.add_sized(
                [420.0, 44.0],
                egui::TextEdit::singleline(&mut self.axml_path)
                    .hint_text("APK 或 AndroidManifest.xml 路径")
                    .text_color(TEXT_MAIN),
            );
            let enter = w.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let enabled = !self.axml_path.trim().is_empty() && !self.running;
            if ui
                .add_enabled(enabled, action_button("▶ 读取指定文件", ACCENT, ACCENT_HOVER))
                .clicked()
                || enter
            {
                let p = self.axml_path.trim().to_string();
                if !p.is_empty() {
                    self.run_axml(&p);
                }
            }
        });
        ui.add_space(6.0);
        ui.separator();

        if !self.manifest_text.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("内容 {} 字符", self.manifest_text.len())).color(TEXT_DIM));
                if ui.add(ghost_button("📄 复制全文")).clicked() {
                    copy_to_clipboard(ui, &self.manifest_text);
                }
            });
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.manifest_text)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(22)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }
    }

    fn run_axml(&mut self, path: &str) {
        let p = path.trim();
        if p.is_empty() || self.running {
            return;
        }
        self.manifest_text.clear();
        self.launch(&["axml".to_string(), p.to_string()], CmdKind::Axml);
    }

    /// 解包 APK 分类界面
    fn extract_tab(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "📦 解包 APK");
        ui.horizontal(|ui| {
            ui.label(RichText::new("输出目录：").strong().size(17.0));
            let mut o = self.extract_output.clone();
            let w = ui.add_sized(
                [340.0, 44.0],
                egui::TextEdit::singleline(&mut o).hint_text("默认 ./<文件名>.unp"),
            );
            if w.changed() {
                self.extract_output = o;
            }
            if ui.add(ghost_button("浏览…")).clicked() {
                if let Some(d) = rfd::FileDialog::new().pick_folder() {
                    self.extract_output = d.display().to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.extract_verbose, RichText::new("显示提取进度 (-v)").size(16.0));
            ui.checkbox(&mut self.extract_resources, RichText::new("解码资源 (-r)").size(16.0));
            ui.checkbox(&mut self.extract_list, RichText::new("仅列出内容 (-l)").size(16.0));
        });
        ui.add_space(4.0);
        ui.label(RichText::new("文件过滤正则：").size(16.0));
        ui.add(
            egui::TextEdit::multiline(&mut self.extract_filter)
                .desired_rows(3)
                .desired_width(640.0)
                .hint_text("例如: AndroidManifest.xml\nclasses\\d+\\.dex"),
        );
        ui.add_space(6.0);
        let enabled = !self.files.is_empty() && !self.running;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(enabled, action_button("▶ 开始解包", GREEN, GREEN_HOVER))
                .clicked()
            {
                self.run_extract(false);
            }
            if ui
                .add_enabled(enabled, action_button("📃 仅列出内容", BLUE, ACCENT_HOVER))
                .clicked()
            {
                self.run_extract(true);
            }
            if !enabled && self.files.is_empty() {
                ui.label(RichText::new("请先在顶部添加 APK 文件。").color(TEXT_DIM).color(TEXT_DIM));
            }
        });
        ui.add_space(4.0);
        ui.separator();
        if !self.extract_log.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("输出 {} 字符", self.extract_log.len())).color(TEXT_DIM));
                if ui.add(ghost_button("📦 复制输出")).clicked() {
                    copy_to_clipboard(ui, &self.extract_log);
                }
            });
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.extract_log)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(20)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }
    }

    fn run_extract(&mut self, list_only: bool) {
        if self.files.is_empty() || self.running {
            return;
        }
        let mut args = vec!["extract".to_string()];
        if list_only {
            args.push("--list".to_string());
        } else {
            if !self.extract_output.trim().is_empty() {
                args.push("--output".to_string());
                args.push(self.extract_output.trim().to_string());
            }
            for line in self.extract_filter.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    args.push("--files".to_string());
                    args.push(l.to_string());
                }
            }
            if self.extract_verbose {
                args.push("--verbose".to_string());
            }
            if self.extract_resources {
                args.push("--resources".to_string());
            }
        }
        args.extend(self.files.iter().cloned());
        self.extract_log.clear();
        self.launch(&args, CmdKind::Extract);
    }

    /// 重打包分类界面
    fn repack_tab(&mut self, ui: &mut egui::Ui) {
        section_heading(ui, "🔧 重打包");
        ui.horizontal(|ui| {
            ui.label(RichText::new("输出文件 -o：").strong().size(17.0));
            let mut o = self.repack_output.clone();
            let w = ui.add_sized(
                [300.0, 44.0],
                egui::TextEdit::singleline(&mut o).hint_text("默认 <源名>.repacked.apk"),
            );
            if w.changed() {
                self.repack_output = o;
            }
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("输出目录 -d：").strong().size(17.0));
            let mut d = self.repack_output_dir.clone();
            let w = ui.add_sized(
                [300.0, 44.0],
                egui::TextEdit::singleline(&mut d).hint_text("默认与源文件同目录"),
            );
            if w.changed() {
                self.repack_output_dir = d;
            }
            if ui.add(ghost_button("浏览…")).clicked() {
                if let Some(f) = rfd::FileDialog::new().pick_folder() {
                    self.repack_output_dir = f.display().to_string();
                }
            }
        });
        ui.add_space(6.0);
        let enabled = !self.files.is_empty() && !self.running;
        if ui
            .add_enabled(enabled, action_button("▶ 开始重打包", ORANGE, egui::Color32::from_rgb(238, 172, 84)))
            .clicked()
        {
            self.run_repack();
        }
        if !enabled && self.files.is_empty() {
            ui.label(RichText::new("请先在顶部添加 APK 文件。").color(TEXT_DIM).color(TEXT_DIM));
        }
        ui.label(RichText::new("注意：重打包结果未签名，仅用于修复损坏的压缩包。").color(TEXT_DIM).size(15.0));
        ui.add_space(4.0);
        ui.separator();
        if !self.repack_log.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("输出 {} 字符", self.repack_log.len())).color(TEXT_DIM));
                if ui.add(ghost_button("🔧 复制输出")).clicked() {
                    copy_to_clipboard(ui, &self.repack_log);
                }
            });
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.repack_log)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(18)
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }
    }

    fn run_repack(&mut self) {
        if self.files.is_empty() || self.running {
            return;
        }
        let mut args = vec!["repack".to_string()];
        if !self.repack_output.trim().is_empty() {
            args.push("--output".to_string());
            args.push(self.repack_output.trim().to_string());
        }
        if !self.repack_output_dir.trim().is_empty() {
            args.push("--output-dir".to_string());
            args.push(self.repack_output_dir.trim().to_string());
        }
        args.extend(self.files.iter().cloned());
        self.repack_log.clear();
        self.launch(&args, CmdKind::Repack);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();

        // 支持环境变量 APKINFO_GUI_OPEN 预加载文件（快捷方式/自动化测试可用）
        if !self.opened_env {
            self.opened_env = true;
            if let Ok(p) = std::env::var("APKINFO_GUI_OPEN") {
                if !p.trim().is_empty() {
                    self.open_path(&p);
                }
            }
        }

        // 拖放 APK 到窗口 -> 加入列表并自动解析
        let dropped: Vec<PathBuf> = ctx
            .input(|i| i.raw.dropped_files.clone())
            .into_iter()
            .filter_map(|f| f.path)
            .collect();
        if !dropped.is_empty() {
            for p in dropped {
                self.open_path(&p.display().to_string());
            }
        }

        // ---------- 顶部：文件选择（大控件） ----------
        egui::TopBottomPanel::top("file_bar").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("📂 APK 文件").strong().size(20.0));
                let mut open_clicked = false;
                let w = ui.add_sized(
                    [420.0, 46.0],
                    egui::TextEdit::singleline(&mut self.path_input)
                        .hint_text("输入 APK 路径，回车或点“打开并解析”")
                        .text_color(TEXT_MAIN),
                );
                if w.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    open_clicked = true;
                }
                if ui
                    .add(action_button("打开并解析 ▶", GREEN, GREEN_HOVER))
                    .clicked()
                {
                    open_clicked = true;
                }
                if open_clicked {
                    let p = self.path_input.clone();
                    self.open_path(&p);
                }
                if ui
                    .add(action_button("📂 浏览…", BLUE, ACCENT_HOVER))
                    .clicked()
                {
                    self.pick_files();
                }
                if !self.files.is_empty() && !self.running {
                    if ui.add(ghost_button("🔄 重新解析")).clicked() {
                        self.analyze_current();
                    }
                    if ui.add(ghost_button("清空")).clicked() {
                        self.files.clear();
                        self.show_results.clear();
                        self.extract_log.clear();
                        self.repack_log.clear();
                        self.manifest_text.clear();
                    }
                }
            });
            ui.add_space(6.0);
            // 醒目的拖放提示
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("💡 提示：将 APK / XAPK / APKM 文件直接拖入本窗口，将自动解析并分类显示结果。")
                        .size(16.0)
                        .color(GREEN_TEXT),
                );
            });
            if !self.files.is_empty() {
                ui.add_space(4.0);
                let mut remove: Option<usize> = None;
                for (i, f) in self.files.iter().enumerate() {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("  {}▶", i + 1)).strong().size(16.0));
                        ui.label(RichText::new(f.as_str()).size(15.0));
                        if ui.small_button("✕").clicked() {
                            remove = Some(i);
                        }
                    });
                }
                if let Some(i) = remove {
                    self.files.remove(i);
                }
            }
            ui.add_space(10.0);
        });

        // ---------- 底部：状态栏 ----------
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let color = if self.running {
                    egui::Color32::from_rgb(215, 130, 38)
                } else if self.status.starts_with("完成") {
                    GREEN_TEXT
                } else if self.status.starts_with("失败") {
                    ERR
                } else {
                    TEXT_DIM
                };
                ui.label(RichText::new("●").color(color).size(14.0));
                ui.label(RichText::new(&self.status).size(16.0));
                if !self.cmd_log.is_empty() {
                    ui.separator();
                    ui.label(RichText::new(&self.cmd_log).color(TEXT_DIM).size(14.0));
                }
            });
        });

        // ---------- 左侧：分类导航（大字号、圆角高亮） ----------
        egui::SidePanel::left("nav")
            .resizable(false)
            .default_width(224.0)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.label(RichText::new("结果分类").strong().size(20.0));
                ui.add_space(8.0);
                let items = [
                    (Tab::Show, "📋 基本信息"),
                    (Tab::Sigs, "🛡️ 签名信息"),
                    (Tab::Axml, "📄 AndroidManifest"),
                    (Tab::Extract, "📦 解包 APK"),
                    (Tab::Repack, "🔧 重打包"),
                ];
                for (tab, label) in items {
                    let selected = self.tab == tab;
                    let fill = if selected { ACCENT } else { egui::Color32::TRANSPARENT };
                    let stroke = if selected {
                        egui::Stroke::new(1.0_f32, ACCENT_HOVER)
                    } else {
                        egui::Stroke::new(1.0_f32, egui::Color32::TRANSPARENT)
                    };
                    let text_color = if selected {
                        egui::Color32::WHITE
                    } else {
                        TEXT_MAIN
                    };
                    let resp = egui::Frame::default()
                        .fill(fill)
                        .stroke(stroke)
                        .rounding(egui::Rounding::same(10.0))
                        .inner_margin(egui::Margin::symmetric(12.0, 12.0))
                        .show(ui, |ui| {
                            ui.add_sized(
                                egui::vec2(170.0, 26.0),
                                egui::Label::new(RichText::new(label).size(18.0).color(text_color)),
                            );
                        })
                        .response
                        .interact(egui::Sense::click());
                    if resp.clicked() {
                        self.tab = tab;
                    }
                }
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(RichText::new("版本: 1.0.13").color(TEXT_DIM).size(14.0));
                ui.label(RichText::new("引擎: apk-info CLI").color(TEXT_DIM).size(14.0));
            });

        // ---------- 中央：当前分类界面 ----------
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.tab {
                Tab::Show => self.show_tab(ui),
                Tab::Sigs => self.sigs_tab(ui),
                Tab::Axml => self.axml_tab(ui),
                Tab::Extract => self.extract_tab(ui),
                Tab::Repack => self.repack_tab(ui),
            }
        });
    }
}

fn run_gui() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("APK Info GUI 1.0.13 — apk-info Windows 图形版")
            .with_inner_size([1180.0, 780.0])
            .with_min_inner_size([940.0, 640.0])
            .with_icon(include_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "apk-info-gui",
        options,
        Box::new(|cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(App::new(cc)))
        }),
    )
}

/// 加载系统中文字体（微软雅黑 / 黑体 / 宋体），保证中文正常显示
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\msyhbd.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "C:\\Windows\\Fonts\\Deng.ttf",
    ];
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .push("cjk".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

/// 程序窗口图标（代码生成：深蓝圆角底 + 绿色安卓机器人）
fn include_icon() -> egui::IconData {
    const S: usize = 64;
    let mut rgba = vec![0u8; S * S * 4];
    let mut px = |x: usize, y: usize, c: [u8; 4]| {
        let i = (y * S + x) * 4;
        rgba[i] = c[0];
        rgba[i + 1] = c[1];
        rgba[i + 2] = c[2];
        rgba[i + 3] = c[3];
    };
    let in_rect = |x: usize, y: usize, x0: usize, x1: usize, y0: usize, y1: usize| -> bool {
        x >= x0 && x < x1 && y >= y0 && y < y1
    };
    for y in 0..S {
        for x in 0..S {
            // 圆角底
            let corner = |cx: usize, cy: usize| (cx * cx + cy * cy) > 14 * 14;
            let edge = (x < 6 && y < 6 && corner(6 - x, 6 - y))
                || (x >= S - 6 && y < 6 && corner(x - (S - 7), 6 - y))
                || (x < 6 && y >= S - 6 && corner(6 - x, y - (S - 7)))
                || (x >= S - 6 && y >= S - 6 && corner(x - (S - 7), y - (S - 7)));
            let bg = if edge {
                [0, 0, 0, 0]
            } else {
                [26, 34, 52, 255]
            };
            // 机器人头（绿色圆角矩形近似）
            let head = in_rect(x, y, 14, 50, 20, 46);
            let ant1 = (x == 13 || x == 14) && y >= 10 && y < 20;
            let ant2 = (x == 49 || x == 50) && y >= 10 && y < 20;
            let eye1 = in_rect(x, y, 21, 25, 30, 37);
            let eye2 = in_rect(x, y, 39, 43, 30, 37);
            let mouth = in_rect(x, y, 27, 37, 42, 46);
            if ant1 || ant2 {
                px(x, y, [96, 230, 150, 255]);
            } else if head && !eye1 && !eye2 && !mouth {
                px(x, y, [64, 208, 120, 255]);
            } else if eye1 || eye2 {
                px(x, y, [255, 255, 255, 255]);
            } else if mouth {
                px(x, y, [30, 42, 40, 255]);
            } else {
                px(x, y, bg);
            }
        }
    }
    egui::IconData {
        rgba,
        width: S as u32,
        height: S as u32,
    }
}
