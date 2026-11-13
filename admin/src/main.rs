//! Postwright Admin – desktop administration app for the Postwright mail server.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod api;

use api::{seg, Client, ConnectError};
use eframe::egui::{self, Align, Color32, Layout, RichText};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Page {
    Overview,
    Domains,
    Users,
    Aliases,
    Queue,
    Filters,
    Import,
    Logs,
}

const PAGES: &[(Page, &str)] = &[
    (Page::Overview, "Overview"),
    (Page::Domains, "Domains"),
    (Page::Users, "Users"),
    (Page::Aliases, "Aliases"),
    (Page::Queue, "Mail queue"),
    (Page::Filters, "Spam & antivirus"),
    (Page::Import, "Import from iRedMail"),
    (Page::Logs, "Logs"),
];

enum Msg {
    LoggedIn(Client, Value),
    LoginFailed(ConnectError),
    Loaded(Page, Result<Value, String>),
    Done(Page, String, Result<Value, String>),
    Dns(String, Result<Value, String>),
}

#[derive(Serialize, Deserialize, Default)]
struct Saved {
    server: String,
    email: String,
    /// Approved certificate fingerprints for self-signed servers.
    pins: BTreeMap<String, String>,
}

fn config_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("Postwright Admin").join("config.json"))
}

fn load_saved() -> Saved {
    config_path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn store_saved(s: &Saved) {
    if let Some(p) = config_path() {
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        let _ = std::fs::write(p, serde_json::to_string_pretty(s).unwrap_or_default());
    }
}

#[derive(Default)]
struct EditUser {
    email: String,
    quota: String,
    password: String,
    enabled: bool,
    admin: bool,
}

struct Confirm {
    text: String,
    method: &'static str,
    path: String,
    page: Page,
    ok: String,
}

struct App {
    saved: Saved,
    password: String,
    login_busy: bool,
    login_error: Option<String>,
    pending_cert: Option<String>,
    client: Option<Client>,
    page: Page,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    busy: u32,
    toast: Option<(String, bool, Instant)>,

    overview: Option<Value>,
    domains: Vec<Value>,
    users: Vec<Value>,
    aliases: Vec<Value>,
    queue: Vec<Value>,
    filters: Option<Value>,
    import: Option<Value>,
    logs: Vec<String>,
    dns: BTreeMap<String, Result<Value, String>>,
    dns_open: Option<String>,

    new_domain: String,
    new_selector: String,
    alias_domain: String,
    alias_target: String,
    catch_all: Option<(String, String)>,
    user_search: String,
    nu_local: String,
    nu_domain: String,
    nu_password: String,
    nu_quota: String,
    nu_admin: bool,
    edit_user: Option<EditUser>,
    confirm: Option<Confirm>,
    alias_search: String,
    na_source: String,
    na_target: String,
    imp_dry: bool,
    imp_no_mail: bool,
    imp_no_cal: bool,
    imp_user: String,
    imp_backend: String,
    log_filter: String,
    log_live: bool,
    last_poll: Instant,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 7.0);
        style.spacing.button_padding = egui::vec2(10.0, 4.0);
        cc.egui_ctx.set_global_style(style);
        let (tx, rx) = channel();
        Self {
            saved: load_saved(),
            password: String::new(),
            login_busy: false,
            login_error: None,
            pending_cert: None,
            client: None,
            page: Page::Overview,
            tx,
            rx,
            busy: 0,
            toast: None,
            overview: None,
            domains: vec![],
            users: vec![],
            aliases: vec![],
            queue: vec![],
            filters: None,
            import: None,
            logs: vec![],
            dns: BTreeMap::new(),
            dns_open: None,
            new_domain: String::new(),
            new_selector: String::new(),
            alias_domain: String::new(),
            alias_target: String::new(),
            catch_all: None,
            user_search: String::new(),
            nu_local: String::new(),
            nu_domain: String::new(),
            nu_password: String::new(),
            nu_quota: String::new(),
            nu_admin: false,
            edit_user: None,
            confirm: None,
            alias_search: String::new(),
            na_source: String::new(),
            na_target: String::new(),
            imp_dry: true,
            imp_no_mail: false,
            imp_no_cal: false,
            imp_user: String::new(),
            imp_backend: String::new(),
            log_filter: String::new(),
            log_live: true,
            last_poll: Instant::now(),
        }
    }

    // ------------------------------------------------------------- networking

    fn login(&mut self, ctx: &egui::Context) {
        self.login_busy = true;
        self.login_error = None;
        let (server, email, pw) = (self.saved.server.clone(), self.saved.email.clone(), self.password.clone());
        let pin = self.saved.pins.get(&api::normalise_url(&server)).cloned();
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let msg = match Client::connect(&server, &email, &pw, pin) {
                Ok((c, v)) => Msg::LoggedIn(c, v),
                Err(e) => Msg::LoginFailed(e),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn spawn(&mut self, ctx: &egui::Context, f: impl FnOnce(&Client) -> Msg + Send + 'static) {
        let Some(c) = self.client.clone() else { return };
        self.busy += 1;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f(&c));
            ctx.request_repaint();
        });
    }

    fn load(&mut self, ctx: &egui::Context, page: Page) {
        let path = match page {
            Page::Overview => "overview".to_string(),
            Page::Domains => "domains".into(),
            Page::Users => "users".into(),
            Page::Aliases => "aliases".into(),
            Page::Queue => "queue".into(),
            Page::Filters => "filters".into(),
            Page::Import => "import".into(),
            Page::Logs => format!("logs?n=800&q={}", seg(&self.log_filter)),
        };
        self.spawn(ctx, move |c| Msg::Loaded(page, c.get(&path)));
        if page == Page::Users {
            // The add-user form needs the domain list.
            self.spawn(ctx, |c| Msg::Loaded(Page::Domains, c.get("domains")));
        }
    }

    fn action(&mut self, ctx: &egui::Context, method: &'static str, path: String, body: Value, page: Page, ok: &str) {
        let ok = ok.to_string();
        self.spawn(ctx, move |c| {
            let r = if method == "DELETE" { c.delete(&path) } else { c.send(method, &path, &body) };
            Msg::Done(page, ok, r)
        });
    }

    fn toast(&mut self, text: impl Into<String>, ok: bool) {
        self.toast = Some((text.into(), ok, Instant::now()));
    }

    fn handle(&mut self, ctx: &egui::Context, m: Msg) {
        match m {
            Msg::LoggedIn(c, v) => {
                self.login_busy = false;
                self.password.clear();
                self.client = Some(c);
                self.overview = Some(v);
                self.page = Page::Overview;
                store_saved(&self.saved);
            }
            Msg::LoginFailed(ConnectError::UntrustedCert(fp)) => {
                self.login_busy = false;
                self.pending_cert = Some(fp);
            }
            Msg::LoginFailed(ConnectError::Other(e)) => {
                self.login_busy = false;
                self.login_error = Some(e);
            }
            Msg::Loaded(page, r) => {
                self.busy = self.busy.saturating_sub(1);
                match r {
                    Ok(v) => {
                        let arr = || v.as_array().cloned().unwrap_or_default();
                        match page {
                            Page::Overview => self.overview = Some(v.clone()),
                            Page::Domains => self.domains = arr(),
                            Page::Users => self.users = arr(),
                            Page::Aliases => self.aliases = arr(),
                            Page::Queue => self.queue = arr(),
                            Page::Filters => self.filters = Some(v.clone()),
                            Page::Import => self.import = Some(v.clone()),
                            Page::Logs => {
                                self.logs = v["lines"].as_array().map(|a| a.iter().filter_map(|l| l.as_str().map(String::from)).collect()).unwrap_or_default()
                            }
                        }
                    }
                    Err(e) => self.toast(e, false),
                }
            }
            Msg::Done(page, ok, r) => {
                self.busy = self.busy.saturating_sub(1);
                match r {
                    Ok(_) => {
                        self.toast(ok, true);
                        self.load(ctx, page);
                        if page == Page::Domains {
                            self.dns.clear();
                        }
                    }
                    Err(e) => self.toast(e, false),
                }
            }
            Msg::Dns(d, r) => {
                self.busy = self.busy.saturating_sub(1);
                self.dns.insert(d, r);
            }
        }
    }

    // ------------------------------------------------------------------- views

    fn login_view(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.add_space(70.0);
        ui.vertical_centered(|ui| {
            ui.heading(RichText::new("Postwright Admin").size(28.0).strong());
            ui.label(RichText::new("Sign in with an administrator account").color(ui.visuals().weak_text_color()));
            ui.add_space(24.0);
            egui::Frame::group(ui.style()).inner_margin(20.0).show(ui, |ui| {
                ui.set_width(380.0);
                egui::Grid::new("login").num_columns(2).spacing([12.0, 12.0]).show(ui, |ui| {
                    ui.label("Server");
                    ui.add(egui::TextEdit::singleline(&mut self.saved.server).hint_text("mail.example.com").desired_width(260.0));
                    ui.end_row();
                    ui.label("Email");
                    ui.add(egui::TextEdit::singleline(&mut self.saved.email).hint_text("you@example.com").desired_width(260.0));
                    ui.end_row();
                    ui.label("Password");
                    let pw = ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(260.0));
                    ui.end_row();
                    let enter = pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.label("");
                    let ready = !self.saved.server.trim().is_empty() && !self.saved.email.trim().is_empty() && !self.password.is_empty();
                    ui.horizontal(|ui| {
                        let b = ui.add_enabled(ready && !self.login_busy, egui::Button::new(RichText::new("Sign in").strong()));
                        if self.login_busy {
                            ui.spinner();
                        }
                        if (b.clicked() || (enter && ready)) && !self.login_busy {
                            self.login(&ctx);
                        }
                    });
                    ui.end_row();
                });
                if let Some(e) = &self.login_error {
                    ui.add_space(8.0);
                    ui.colored_label(Color32::from_rgb(0xc0, 0x39, 0x2b), e);
                }
            });
            ui.add_space(10.0);
            ui.label(
                RichText::new("Administration only works from the networks listed in security.admin_networks (your LAN by default).")
                    .small()
                    .color(ui.visuals().weak_text_color()),
            );
        });

        if let Some(fp) = self.pending_cert.clone() {
            let mut decision: Option<bool> = None;
            egui::Window::new("Untrusted certificate")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(&ctx, |ui| {
                    ui.set_max_width(460.0);
                    ui.label("This server's certificate isn't signed by a public authority (it may be self-signed).");
                    ui.label("Only trust it if this fingerprint matches the one on your server:");
                    ui.add_space(6.0);
                    ui.label(RichText::new(&fp).monospace().small());
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("On the server: openssl x509 -in cert.pem -noout -fingerprint -sha256").small().color(ui.visuals().weak_text_color()),
                    );
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Trust this certificate").clicked() {
                            decision = Some(true);
                        }
                        if ui.button("Cancel").clicked() {
                            decision = Some(false);
                        }
                    });
                });
            match decision {
                Some(true) => {
                    self.saved.pins.insert(api::normalise_url(&self.saved.server), fp);
                    self.pending_cert = None;
                    self.login(&ctx);
                }
                Some(false) => self.pending_cert = None,
                None => {}
            }
        }
    }

    fn header(&mut self, ui: &mut egui::Ui, title: &str, sub: &str) {
        ui.horizontal(|ui| {
            ui.heading(RichText::new(title).size(22.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    let ctx = ui.ctx().clone();
                    self.load(&ctx, self.page);
                }
                if self.busy > 0 {
                    ui.spinner();
                }
            });
        });
        if !sub.is_empty() {
            ui.label(RichText::new(sub).color(ui.visuals().weak_text_color()));
        }
        ui.add_space(10.0);
    }

    fn overview_view(&mut self, ui: &mut egui::Ui) {
        let Some(o) = self.overview.clone() else {
            self.header(ui, "Overview", "");
            return;
        };
        let up = o["uptime_secs"].as_u64().unwrap_or(0);
        self.header(ui, "Overview", &format!("{} · Postwright v{} · up {}", s(&o["hostname"]), s(&o["version"]), uptime(up)));
        let c = &o["counts"];
        stats(
            ui,
            &[
                (c["users"].to_string(), "Users"),
                (c["domains"].to_string(), "Domains"),
                (c["aliases"].to_string(), "Aliases"),
                (c["messages"].to_string(), "Messages"),
                (bytes(c["unique_bytes"].as_i64().unwrap_or(0)), "Storage used"),
                (c["queue"].to_string(), "Outbound queue"),
                (c["calendars"].to_string(), "Calendars"),
                (o["recent_warnings"].to_string(), "Recent warnings"),
            ],
        );
        ui.add_space(12.0);
        card(ui, "Server identity", |ui| {
            egui::Grid::new("ident").num_columns(2).spacing([24.0, 8.0]).show(ui, |ui| {
                let d = &o["server_dns"];
                ui.label("Host name");
                ui.label(RichText::new(s(&o["hostname"])).monospace());
                ui.end_row();
                ui.label("Addresses");
                let addrs = list(&d["addresses"]);
                if addrs.is_empty() {
                    pill(ui, "No A/AAAA record", Tone::Bad);
                } else {
                    ui.label(addrs.join(", "));
                }
                ui.end_row();
                ui.label("Reverse DNS");
                ui.horizontal(|ui| {
                    if d["ptr_matches"].as_bool().unwrap_or(false) {
                        pill(ui, "Matches host name", Tone::Good);
                    } else {
                        pill(ui, "Doesn't match", Tone::Warn);
                    }
                    ui.label(RichText::new(list(&d["ptr"]).join(", ")).small());
                });
                ui.end_row();
            });
        });
        scanners_card(ui, &o["scanners"]);
    }

    fn domains_view(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "Domains", "Each domain has its own DKIM key. Check DNS shows what to publish and what's live.");
        let ctx = ui.ctx().clone();
        let domains = self.domains.clone();
        card(ui, "", |ui| {
            egui::Grid::new("domains").num_columns(7).striped(true).spacing([18.0, 8.0]).show(ui, |ui| {
                for h in ["Domain", "Type", "Users", "Aliases", "DKIM", "Catch-all", ""] {
                    ui.label(RichText::new(h).small().strong());
                }
                ui.end_row();
                for d in &domains {
                    let name = s(&d["name"]);
                    ui.label(RichText::new(&name).strong());
                    match d["alias_of"].as_str() {
                        Some(t) => pill(ui, &format!("Alias of {t}"), Tone::Info),
                        None => pill(ui, "Domain", Tone::Good),
                    }
                    ui.label(d["users"].to_string());
                    ui.label(d["aliases"].to_string());
                    ui.label(RichText::new(d["dkim_selector"].as_str().unwrap_or("–")).monospace());
                    ui.label(d["catch_all"].as_str().unwrap_or("–"));
                    ui.horizontal(|ui| {
                        if ui.button("Check DNS").clicked() {
                            self.dns_open = Some(name.clone());
                            let n = name.clone();
                            self.spawn(&ctx, move |c| Msg::Dns(n.clone(), c.get(&format!("domains/{}/dns", seg(&n)))));
                        }
                        if d["alias_of"].is_null() && ui.button("Catch-all").clicked() {
                            self.catch_all = Some((name.clone(), d["catch_all"].as_str().unwrap_or("").to_string()));
                        }
                        if ui.button(RichText::new("Remove").color(bad())).clicked() {
                            self.confirm = Some(Confirm {
                                text: format!("Remove {name}? It must have no users left."),
                                method: "DELETE",
                                path: format!("domains/{}", seg(&name)),
                                page: Page::Domains,
                                ok: "Domain removed".into(),
                            });
                        }
                    });
                    ui.end_row();
                }
            });
            if domains.is_empty() {
                ui.label("No domains yet.");
            }
        });
        card(ui, "Add a domain", |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.new_domain).hint_text("example.com").desired_width(260.0));
                ui.label("DKIM selector");
                ui.add(egui::TextEdit::singleline(&mut self.new_selector).hint_text("pw1").desired_width(70.0));
                if ui.button("Add domain").clicked() {
                    let body = json!({"name": self.new_domain.trim(), "selector": self.new_selector.trim()});
                    self.new_domain.clear();
                    self.action(&ctx, "POST", "domains".into(), body, Page::Domains, "Domain added; now publish its DNS records");
                }
            });
        });
        card(ui, "Add an alias domain", |ui| {
            ui.label(RichText::new("Mail to anyone@alias goes to the same mailbox at the target domain.").small());
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.alias_domain).hint_text("example.net").desired_width(220.0));
                ui.label("to");
                let targets: Vec<String> = domains.iter().filter(|d| d["alias_of"].is_null()).map(|d| s(&d["name"])).collect();
                if self.alias_target.is_empty() {
                    self.alias_target = targets.first().cloned().unwrap_or_default();
                }
                egui::ComboBox::from_id_salt("alias_target").selected_text(&self.alias_target).show_ui(ui, |ui| {
                    for t in &targets {
                        ui.selectable_value(&mut self.alias_target, t.clone(), t);
                    }
                });
                if ui.button("Add alias domain").clicked() {
                    let body = json!({"alias": self.alias_domain.trim(), "target": self.alias_target});
                    self.alias_domain.clear();
                    self.action(&ctx, "POST", "domains/alias".into(), body, Page::Domains, "Alias domain added");
                }
            });
        });

        if let Some(name) = self.dns_open.clone() {
            let mut open = true;
            let entry = self.dns.get(&name).cloned();
            egui::Window::new(format!("DNS records – {name}")).open(&mut open).default_width(760.0).show(&ctx, |ui| match entry {
                None => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Checking DNS…");
                    });
                }
                Some(Err(e)) => {
                    ui.colored_label(bad(), e);
                }
                Some(Ok(v)) => {
                    ui.set_max_width(760.0);
                    egui::ScrollArea::vertical().max_height(560.0).show(ui, |ui| {
                        for r in v["records"].as_array().cloned().unwrap_or_default() {
                            ui.horizontal(|ui| {
                                match r["status"].as_str() {
                                    Some("ok") => pill(ui, "Live", Tone::Good),
                                    Some("different") => pill(ui, "Different", Tone::Warn),
                                    _ => pill(ui, "Missing", Tone::Bad),
                                }
                                ui.label(RichText::new(s(&r["type"])).strong());
                                ui.label(RichText::new(s(&r["name"])).monospace());
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.button("Copy value").clicked() {
                                        ui.ctx().copy_text(s(&r["expected"]));
                                        self.toast("Copied", true);
                                    }
                                });
                            });
                            ui.add(egui::Label::new(RichText::new(s(&r["expected"])).monospace().small()).wrap());
                            if r["status"].as_str() == Some("different") {
                                ui.label(RichText::new(format!("Currently: {}", s(&r["found"]))).small().color(ui.visuals().weak_text_color()));
                            }
                            ui.separator();
                        }
                    });
                }
            });
            if !open {
                self.dns_open = None;
            }
        }
        if let Some((d, mut target)) = self.catch_all.take() {
            let mut keep = true;
            egui::Window::new(format!("Catch-all for {d}")).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(
                &ctx,
                |ui| {
                    ui.label("Mail to unknown addresses at this domain goes to:");
                    ui.add(egui::TextEdit::singleline(&mut target).hint_text("leave blank to turn off").desired_width(300.0));
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            let body = json!({"catch_all": target.trim()});
                            self.action(&ctx, "PUT", format!("domains/{}", seg(&d)), body, Page::Domains, "Catch-all updated");
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                },
            );
            if keep {
                self.catch_all = Some((d, target));
            }
        }
    }

    fn users_view(&mut self, ui: &mut egui::Ui) {
        let n = self.users.len();
        self.header(ui, "Users", &format!("{n} mailbox{}", if n == 1 { "" } else { "es" }));
        let ctx = ui.ctx().clone();
        let users = self.users.clone();
        card(ui, "", |ui| {
            ui.add(egui::TextEdit::singleline(&mut self.user_search).hint_text("Search users").desired_width(f32::INFINITY));
            ui.add_space(6.0);
            let q = self.user_search.to_ascii_lowercase();
            let w = ui.available_width();
            let cols = [w * 0.36, w * 0.2, w * 0.26];
            ui.horizontal(|ui| {
                for (h, cw) in ["User", "Storage", "Status"].iter().zip(cols) {
                    cell(ui, cw, |ui| ui.label(RichText::new(*h).small().strong()));
                }
            });
            ui.separator();
            for u in users.iter().filter(|u| q.is_empty() || s(&u["email"]).contains(&q) || list(&u["addresses"]).iter().any(|a| a.contains(&q))) {
                let email = s(&u["email"]);
                let used = u["used_bytes"].as_i64().unwrap_or(0);
                let quota = u["quota_bytes"].as_i64().unwrap_or(0);
                ui.horizontal(|ui| {
                    cell(ui, cols[0], |ui| {
                        ui.label(RichText::new(&email).strong());
                        let also = list(&u["addresses"]);
                        if !also.is_empty() {
                            ui.add(egui::Label::new(RichText::new(format!("also {}", also.join(", "))).small()).wrap());
                        }
                        let fwd = list(&u["forwards_to"]);
                        if !fwd.is_empty() {
                            ui.add(egui::Label::new(RichText::new(format!("forwards to {}", fwd.join(", "))).small()).wrap());
                        }
                    });
                    cell(ui, cols[1], |ui| {
                        if quota > 0 {
                            ui.add(egui::ProgressBar::new((used as f32 / quota as f32).min(1.0)).desired_width(cols[1] - 20.0).desired_height(6.0));
                        }
                        ui.label(format!("{} / {}", bytes(used), if quota > 0 { bytes(quota) } else { "unlimited".into() }));
                    });
                    cell(ui, cols[2], |ui| {
                        ui.horizontal_wrapped(|ui| {
                            if u["enabled"].as_bool().unwrap_or(false) {
                                pill(ui, "Active", Tone::Good);
                            } else {
                                pill(ui, "Disabled", Tone::Bad);
                            }
                            if u["admin"].as_bool().unwrap_or(false) {
                                pill(ui, "Admin", Tone::Info);
                            }
                            if u["out_of_office"].as_bool().unwrap_or(false) {
                                pill(ui, "Out of office", Tone::Warn);
                            }
                            if u["legacy_password"].as_bool().unwrap_or(false) {
                                pill(ui, "Imported password", Tone::Info);
                            }
                        });
                    });
                    if ui.button("Edit").clicked() {
                        self.edit_user = Some(EditUser {
                            email: email.clone(),
                            quota: (quota / 1_048_576).to_string(),
                            password: String::new(),
                            enabled: u["enabled"].as_bool().unwrap_or(true),
                            admin: u["admin"].as_bool().unwrap_or(false),
                        });
                    }
                    if ui.button(RichText::new("Delete").color(bad())).clicked() {
                        self.confirm = Some(Confirm {
                            text: format!("Delete {email} and ALL their mail and calendars? This can't be undone."),
                            method: "DELETE",
                            path: format!("users/{}", seg(&email)),
                            page: Page::Users,
                            ok: "User deleted".into(),
                        });
                    }
                });
                ui.separator();
            }
        });
        let doms: Vec<String> = self.domains.iter().filter(|d| d["alias_of"].is_null()).map(|d| s(&d["name"])).collect();
        card(ui, "Add a user", |ui| {
            if doms.is_empty() {
                ui.label("Add a domain first.");
                return;
            }
            if !doms.contains(&self.nu_domain) {
                self.nu_domain = doms[0].clone();
            }
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.nu_local).hint_text("name").desired_width(130.0));
                ui.label("@");
                egui::ComboBox::from_id_salt("nu_domain").selected_text(&self.nu_domain).show_ui(ui, |ui| {
                    for d in &doms {
                        ui.selectable_value(&mut self.nu_domain, d.clone(), d);
                    }
                });
                ui.add(egui::TextEdit::singleline(&mut self.nu_password).password(true).hint_text("Password (10+ characters)").desired_width(200.0));
                ui.add(egui::TextEdit::singleline(&mut self.nu_quota).hint_text("Quota MB").desired_width(80.0));
                ui.checkbox(&mut self.nu_admin, "Administrator");
                if ui.button("Add user").clicked() {
                    let body = json!({
                        "email": format!("{}@{}", self.nu_local.trim(), self.nu_domain),
                        "password": self.nu_password, "quota_mb": self.nu_quota.trim().parse::<i64>().unwrap_or(0), "admin": self.nu_admin
                    });
                    self.nu_password.clear();
                    self.nu_local.clear();
                    self.action(&ctx, "POST", "users".into(), body, Page::Users, "User created");
                }
            });
        });

        if let Some(mut e) = self.edit_user.take() {
            let mut keep = true;
            egui::Window::new(format!("Edit {}", e.email)).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(
                &ctx,
                |ui| {
                    egui::Grid::new("edit").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
                        ui.label("Quota (MB, 0 = unlimited)");
                        ui.add(egui::TextEdit::singleline(&mut e.quota).desired_width(100.0));
                        ui.end_row();
                        ui.label("New password");
                        ui.add(egui::TextEdit::singleline(&mut e.password).password(true).hint_text("leave blank to keep").desired_width(220.0));
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(&mut e.enabled, "Enabled");
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(&mut e.admin, "Administrator");
                        ui.end_row();
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            let body = json!({
                                "quota_mb": e.quota.trim().parse::<i64>().unwrap_or(0),
                                "password": if e.password.is_empty() { Value::Null } else { Value::String(e.password.clone()) },
                                "enabled": e.enabled, "admin": e.admin,
                            });
                            self.action(&ctx, "PUT", format!("users/{}", seg(&e.email)), body, Page::Users, "Saved");
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                        }
                    });
                },
            );
            if keep {
                self.edit_user = Some(e);
            }
        }
    }

    fn aliases_view(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "Aliases", "Addresses that deliver to mailboxes or forward elsewhere. One address can go to several targets.");
        let ctx = ui.ctx().clone();
        let aliases = self.aliases.clone();
        card(ui, "", |ui| {
            ui.add(egui::TextEdit::singleline(&mut self.alias_search).hint_text("Search aliases").desired_width(f32::INFINITY));
            ui.add_space(6.0);
            let q = self.alias_search.to_ascii_lowercase();
            egui::Grid::new("aliases").num_columns(3).striped(true).spacing([18.0, 6.0]).show(ui, |ui| {
                for h in ["Address", "Delivers to", ""] {
                    ui.label(RichText::new(h).small().strong());
                }
                ui.end_row();
                for a in aliases.iter().filter(|a| q.is_empty() || s(&a["source"]).contains(&q) || s(&a["target"]).contains(&q)) {
                    let (src, dst) = (s(&a["source"]), s(&a["target"]));
                    ui.horizontal(|ui| {
                        ui.label(&src);
                        if src == dst {
                            pill(ui, "keeps a copy", Tone::Info);
                        }
                    });
                    ui.label(dst.clone());
                    if ui.button(RichText::new("Remove").color(bad())).clicked() {
                        self.action(&ctx, "DELETE", format!("aliases/{}/{}", seg(&src), seg(&dst)), Value::Null, Page::Aliases, "Alias removed");
                    }
                    ui.end_row();
                }
            });
        });
        card(ui, "Add an alias", |ui| {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.na_source).hint_text("sales@example.com").desired_width(240.0));
                ui.label("to");
                ui.add(egui::TextEdit::singleline(&mut self.na_target).hint_text("tony@example.com or an external address").desired_width(300.0));
                if ui.button("Add").clicked() {
                    let body = json!({"source": self.na_source.trim(), "target": self.na_target.trim()});
                    self.na_source.clear();
                    self.na_target.clear();
                    self.action(&ctx, "POST", "aliases".into(), body, Page::Aliases, "Alias added");
                }
            });
        });
    }

    fn queue_view(&mut self, ui: &mut egui::Ui) {
        let n = self.queue.len();
        self.header(ui, "Mail queue", &if n == 0 { "Nothing waiting – all outbound mail has been delivered.".into() } else { format!("{n} message(s) waiting for delivery") });
        let ctx = ui.ctx().clone();
        if ui.add_enabled(n > 0, egui::Button::new("Retry all now")).clicked() {
            self.action(&ctx, "POST", "queue/flush".into(), json!({}), Page::Queue, "Retrying now");
        }
        ui.add_space(8.0);
        if n == 0 {
            return;
        }
        let queue = self.queue.clone();
        card(ui, "", |ui| {
            let w = ui.available_width();
            let cols = [w * 0.2, w * 0.24, w * 0.08, w * 0.1, w * 0.28];
            ui.horizontal(|ui| {
                for (h, cw) in ["From", "To", "Attempts", "Next try", "Last error"].iter().zip(cols) {
                    cell(ui, cw, |ui| ui.label(RichText::new(*h).small().strong()));
                }
            });
            ui.separator();
            for q in &queue {
                ui.horizontal(|ui| {
                    let from = s(&q["from"]);
                    cell(ui, cols[0], |ui| ui.add(egui::Label::new(if from.is_empty() { "<> (bounce)".into() } else { from }).wrap()));
                    cell(ui, cols[1], |ui| ui.add(egui::Label::new(list(&q["recipients"]).join(", ")).wrap()));
                    cell(ui, cols[2], |ui| ui.label(q["attempts"].to_string()));
                    cell(ui, cols[3], |ui| ui.label(when(q["next_attempt"].as_i64().unwrap_or(0))));
                    cell(ui, cols[4], |ui| ui.add(egui::Label::new(RichText::new(q["last_error"].as_str().unwrap_or("")).small()).wrap()));
                    if ui.button(RichText::new("Delete").color(bad())).clicked() {
                        self.confirm = Some(Confirm {
                            text: "Delete this message without delivering it?".into(),
                            method: "DELETE",
                            path: format!("queue/{}", q["id"]),
                            page: Page::Queue,
                            ok: "Deleted".into(),
                        });
                    }
                });
                ui.separator();
            }
        });
    }

    fn filters_view(&mut self, ui: &mut egui::Ui) {
        let Some(f) = self.filters.clone() else {
            self.header(ui, "Spam & antivirus", "");
            return;
        };
        let on = f["enabled"].as_bool().unwrap_or(false);
        self.header(ui, "Spam & antivirus", if on { "Filtering is on." } else { "Filtering is off (filter.enabled = false)." });
        stats(
            ui,
            &[
                (f["junk_score"].to_string(), "Junk folder at score"),
                (f["reject_score"].to_string(), "Reject at score"),
                (format!("{} ms", f["greet_pause_ms"]), "Greeting pause"),
                ((if f["scan_outbound"].as_bool().unwrap_or(false) { "Yes" } else { "No" }).to_string(), "Scan outgoing mail"),
            ],
        );
        ui.add_space(12.0);
        scanners_card(ui, &f["scanners"]);
        card(ui, "DNS blocklists", |ui| {
            egui::Grid::new("dnsbl").num_columns(2).spacing([24.0, 6.0]).show(ui, |ui| {
                for d in f["dnsbl"].as_array().cloned().unwrap_or_default() {
                    ui.label(RichText::new(s(&d["zone"])).monospace());
                    ui.label(format!("+{}", d["score"]));
                    ui.end_row();
                }
            });
        });
        ui.label(RichText::new("These settings live in postwright.toml; restart the server after changing them.").small());
    }

    fn import_view(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "Import from iRedMail", "Runs on the server, so Postwright must be installed on the iRedMail machine (as root). Safe to run more than once.");
        let ctx = ui.ctx().clone();
        let st = self.import.clone().unwrap_or(Value::Null);
        let running = st["running"].as_bool().unwrap_or(false);
        card(ui, "", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut self.imp_dry, "Dry run (just show what would be imported)");
                ui.checkbox(&mut self.imp_no_mail, "Accounts only (skip mail)");
                ui.checkbox(&mut self.imp_no_cal, "Skip calendars");
            });
            ui.horizontal(|ui| {
                let label = match self.imp_backend.as_str() {
                    "mysql" => "MariaDB / MySQL",
                    "pgsql" => "PostgreSQL",
                    "ldap" => "OpenLDAP",
                    _ => "Detect automatically",
                };
                egui::ComboBox::from_id_salt("backend").selected_text(label).show_ui(ui, |ui| {
                    for (v, l) in [("", "Detect automatically"), ("mysql", "MariaDB / MySQL"), ("pgsql", "PostgreSQL"), ("ldap", "OpenLDAP")] {
                        ui.selectable_value(&mut self.imp_backend, v.to_string(), l);
                    }
                });
                ui.add(egui::TextEdit::singleline(&mut self.imp_user).hint_text("only this user (optional)").desired_width(240.0));
                if ui.add_enabled(!running, egui::Button::new("Start")).clicked() {
                    if self.imp_dry {
                        self.start_import(&ctx);
                    } else {
                        self.confirm = Some(Confirm {
                            text: "Run the real import now?".into(),
                            method: "POST",
                            path: "import/iredmail".into(),
                            page: Page::Import,
                            ok: "Import started".into(),
                        });
                    }
                }
                if running {
                    ui.spinner();
                    pill(ui, "Running…", Tone::Warn);
                } else if st["finished"].as_bool().unwrap_or(false) {
                    if st["ok"].as_bool().unwrap_or(false) {
                        pill(ui, "Finished", Tone::Good);
                    } else {
                        pill(ui, &format!("Failed: {}", st["error"].as_str().unwrap_or("")), Tone::Bad);
                    }
                }
            });
        });
        card(ui, "Output", |ui| {
            let out = list(&st["output"]);
            let text = if out.is_empty() { "No import has run yet.".to_string() } else { out.join("\n") };
            egui::ScrollArea::vertical().max_height(420.0).stick_to_bottom(true).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(text).monospace()).wrap());
            });
        });
    }

    fn import_body(&self) -> Value {
        json!({"dry_run": self.imp_dry, "no_mail": self.imp_no_mail, "no_calendars": self.imp_no_cal, "user": self.imp_user.trim(), "backend": self.imp_backend})
    }

    fn start_import(&mut self, ctx: &egui::Context) {
        let body = self.import_body();
        self.action(ctx, "POST", "import/iredmail".into(), body, Page::Import, "Import started");
    }

    fn logs_view(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "Logs", "The most recent 2,000 lines are kept in memory on the server.");
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut self.log_filter).hint_text("Filter, e.g. WARN or an address").desired_width(360.0));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                self.load(&ctx, Page::Logs);
            }
            ui.checkbox(&mut self.log_live, "Live");
        });
        ui.add_space(6.0);
        let text = if self.logs.is_empty() { "Nothing matches.".to_string() } else { self.logs.join("\n") };
        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::ScrollArea::both().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                ui.add(egui::Label::new(RichText::new(text).monospace()).extend());
            });
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        while let Ok(m) = self.rx.try_recv() {
            self.handle(&ctx, m);
        }

        if self.client.is_none() {
            egui::CentralPanel::default().show(ui, |ui| self.login_view(ui));
            return;
        }

        // Live views poll the server.
        let poll_every = match self.page {
            Page::Logs if self.log_live => Some(Duration::from_secs(3)),
            Page::Import if self.import.as_ref().and_then(|v| v["running"].as_bool()).unwrap_or(false) => Some(Duration::from_secs(2)),
            Page::Overview | Page::Queue => Some(Duration::from_secs(30)),
            _ => None,
        };
        if let Some(every) = poll_every {
            if self.last_poll.elapsed() >= every && self.busy == 0 {
                self.last_poll = Instant::now();
                self.load(&ctx, self.page);
            }
            ctx.request_repaint_after(every);
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Postwright").strong().size(16.0));
                ui.label(RichText::new(self.client.as_ref().map(|c| c.base().to_string()).unwrap_or_default()).color(ui.visuals().weak_text_color()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Sign out").clicked() {
                        self.client = None;
                        self.overview = None;
                    }
                    ui.label(&self.saved.email);
                });
            });
            ui.add_space(4.0);
        });

        egui::Panel::left("nav").exact_size(190.0).show(ui, |ui| {
            ui.add_space(8.0);
            for (p, label) in PAGES {
                let selected = self.page == *p;
                let b = ui.add_sized([174.0, 30.0], egui::Button::selectable(selected, *label));
                if b.clicked() && !selected {
                    self.page = *p;
                    self.last_poll = Instant::now();
                    self.load(&ctx, *p);
                }
            }
        });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_space(6.0);
                match self.page {
                    Page::Overview => self.overview_view(ui),
                    Page::Domains => self.domains_view(ui),
                    Page::Users => self.users_view(ui),
                    Page::Aliases => self.aliases_view(ui),
                    Page::Queue => self.queue_view(ui),
                    Page::Filters => self.filters_view(ui),
                    Page::Import => self.import_view(ui),
                    Page::Logs => self.logs_view(ui),
                }
            });
        });

        // Confirmation dialog for destructive actions.
        if let Some(c) = self.confirm.take() {
            let mut answer: Option<bool> = None;
            egui::Window::new("Please confirm").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(&ctx, |ui| {
                ui.label(&c.text);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Yes, go ahead").color(bad())).clicked() {
                        answer = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        answer = Some(false);
                    }
                });
            });
            match answer {
                Some(true) => {
                    let body = if c.page == Page::Import { self.import_body() } else { Value::Null };
                    self.action(&ctx, c.method, c.path, body, c.page, &c.ok);
                }
                Some(false) => {}
                None => self.confirm = Some(c),
            }
        }

        // Toast
        if let Some((text, ok, at)) = self.toast.clone() {
            let life = if ok { 2.5 } else { 6.0 };
            if at.elapsed().as_secs_f32() > life {
                self.toast = None;
            } else {
                egui::Area::new(egui::Id::unique("toast")).anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -16.0]).show(&ctx, |ui| {
                    egui::Frame::new()
                        .fill(if ok { Color32::from_rgb(0x2e, 0x7d, 0x32) } else { Color32::from_rgb(0xb3, 0x26, 0x1e) })
                        .corner_radius(8.0)
                        .inner_margin(egui::Margin::symmetric(14, 10))
                        .show(ui, |ui| ui.label(RichText::new(text).color(Color32::WHITE).strong()));
                });
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }
    }
}

// ------------------------------------------------------------------- helpers

#[derive(Clone, Copy)]
enum Tone {
    Good,
    Warn,
    Bad,
    Info,
}

fn bad() -> Color32 {
    Color32::from_rgb(0xc0, 0x39, 0x2b)
}

fn pill(ui: &mut egui::Ui, text: &str, tone: Tone) {
    let dark = ui.visuals().dark_mode;
    let (fg, bg) = match (tone, dark) {
        (Tone::Good, false) => (Color32::from_rgb(0x2e, 0x7d, 0x32), Color32::from_rgb(0xe5, 0xf2, 0xe6)),
        (Tone::Warn, false) => (Color32::from_rgb(0xa1, 0x5c, 0x00), Color32::from_rgb(0xfb, 0xef, 0xdc)),
        (Tone::Bad, false) => (Color32::from_rgb(0xb3, 0x26, 0x1e), Color32::from_rgb(0xfa, 0xe3, 0xe1)),
        (Tone::Info, false) => (Color32::from_rgb(0x1f, 0x5f, 0x8b), Color32::from_rgb(0xe6, 0xee, 0xf5)),
        (Tone::Good, true) => (Color32::from_rgb(0x7c, 0xc4, 0x7f), Color32::from_rgb(0x1c, 0x2b, 0x1d)),
        (Tone::Warn, true) => (Color32::from_rgb(0xe2, 0xa2, 0x4c), Color32::from_rgb(0x2e, 0x24, 0x14)),
        (Tone::Bad, true) => (Color32::from_rgb(0xf0, 0x8a, 0x80), Color32::from_rgb(0x33, 0x1c, 0x1a)),
        (Tone::Info, true) => (Color32::from_rgb(0x6a, 0xa9, 0xd8), Color32::from_rgb(0x1d, 0x2a, 0x36)),
    };
    egui::Frame::new().fill(bg).corner_radius(9.0).inner_margin(egui::Margin::symmetric(8, 1)).show(ui, |ui| {
        ui.label(RichText::new(text).color(fg).small().strong());
    });
}

fn card(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style()).inner_margin(14.0).corner_radius(8.0).show(ui, |ui| {
        ui.set_width(ui.available_width());
        if !title.is_empty() {
            ui.label(RichText::new(title).strong().size(15.0));
            ui.add_space(4.0);
        }
        add(ui);
    });
    ui.add_space(10.0);
}

/// A fixed-width table cell (egui grids shrink columns that contain wrapping text).
fn cell<R>(ui: &mut egui::Ui, w: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.allocate_ui_with_layout(egui::vec2(w, 0.0), Layout::top_down(Align::Min), |ui| {
        ui.set_width(w);
        add(ui)
    })
    .inner
}

/// Stat tiles laid out in rows that fit the window (framed widgets don't wrap in egui).
fn stats(ui: &mut egui::Ui, items: &[(String, &str)]) {
    const W: f32 = 150.0;
    let gap = ui.spacing().item_spacing.x;
    let per = (((ui.available_width() + gap) / (W + 26.0 + gap)).floor() as usize).max(1);
    for row in items.chunks(per) {
        ui.horizontal(|ui| {
            for (n, l) in row {
                stat(ui, n, l, W);
            }
        });
    }
}

fn stat(ui: &mut egui::Ui, n: &str, label: &str, w: f32) {
    egui::Frame::group(ui.style()).inner_margin(12.0).corner_radius(8.0).show(ui, |ui| {
        ui.set_width(w);
        ui.vertical(|ui| {
            ui.label(RichText::new(n).size(22.0).strong());
            ui.label(RichText::new(label.to_uppercase()).small().color(ui.visuals().weak_text_color()));
        });
    });
}

fn scanners_card(ui: &mut egui::Ui, scanners: &Value) {
    card(ui, "Scanners", |ui| {
        let list = scanners.as_array().cloned().unwrap_or_default();
        if list.is_empty() {
            ui.label("No ClamAV, Rspamd or SpamAssassin configured. Built-in checks still run.");
            return;
        }
        egui::Grid::new(ui.next_auto_id()).num_columns(3).spacing([24.0, 6.0]).show(ui, |ui| {
            for sc in list {
                ui.label(s(&sc["name"]));
                ui.label(RichText::new(s(&sc["address"])).monospace());
                ui.horizontal(|ui| {
                    if sc["ok"].as_bool().unwrap_or(false) {
                        pill(ui, "Responding", Tone::Good);
                    } else {
                        pill(ui, "Down", Tone::Bad);
                        ui.label(RichText::new(s(&sc["detail"])).small());
                    }
                });
                ui.end_row();
            }
        });
    });
}

fn s(v: &Value) -> String {
    v.as_str().map(String::from).unwrap_or_else(|| if v.is_null() { String::new() } else { v.to_string() })
}

fn list(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().map(s).collect()).unwrap_or_default()
}

fn bytes(b: i64) -> String {
    let mut f = b as f64;
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut i = 0;
    while f >= 1024.0 && i < units.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{f:.1} {}", units[i])
    }
}

fn uptime(s: u64) -> String {
    let (d, h, m) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

fn when(ts: i64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let d = ts - now;
    if d <= 0 {
        "now".into()
    } else if d < 3600 {
        format!("in {} min", d / 60 + 1)
    } else {
        format!("in {:.1} h", d as f64 / 3600.0)
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1240.0, 800.0]).with_min_inner_size([900.0, 560.0]).with_title("Postwright Admin"),
        ..Default::default()
    };
    eframe::run_native("Postwright Admin", options, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}
