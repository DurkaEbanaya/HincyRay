use std::{
    cmp::Reverse,
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arboard::Clipboard;
use eframe::egui::{self, Color32, Frame, Margin, RichText, ScrollArea, Sense, Stroke};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};

use crate::{
    profiles::{Profile, SubscriptionSource, load_subscription_detailed, parse_input},
    tester::{self, TestResult, TestSettings, TestStatus, TestUpdate},
    theme,
};

pub struct XrayVpnTestApp {
    input: String,
    profiles: Vec<Profile>,
    subscriptions: Vec<SubscriptionSource>,
    candidate_count: usize,
    unsupported_placeholders: usize,
    results: Vec<TestResult>,
    receiver: Option<Receiver<TestUpdate>>,
    cancel_test: Option<Arc<AtomicBool>>,
    testing: bool,
    total_tests: usize,
    completed_tests: usize,
    status: String,
    debug: String,
    favorites: HashSet<String>,
    favorite_profiles: Vec<Profile>,
    show_favorites_only: bool,
    settings_open: bool,
    statistics_open: bool,
    stats_interval_minutes: u64,
    stats_auto_enabled: bool,
    stats_next_run: Option<SystemTime>,
    stats_history: Vec<StatSample>,
    stats_resource_path: String,
    stats_status: String,
    collect_stats_for_run: bool,
    settings: TestSettings,
}

#[derive(Default, Serialize, Deserialize)]
struct PersistedState {
    input: String,
    profiles: Vec<Profile>,
    results: Vec<TestResult>,
    favorites: Vec<String>,
    favorite_profiles: Vec<Profile>,
    stats_interval_minutes: u64,
    stats_history: Vec<StatSample>,
    stats_resource_path: String,
    settings: TestSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StatSample {
    timestamp: u64,
    profile_raw: String,
    profile_name: String,
    score: u32,
    passed: bool,
    latency_ms: u32,
    download_mbps: f32,
}

impl XrayVpnTestApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        let persisted = load_persisted_state();
        let mut profiles = persisted.profiles;
        merge_profiles_by_raw(&mut profiles, persisted.favorite_profiles.clone());
        for (id, profile) in profiles.iter_mut().enumerate() {
            profile.id = id;
        }
        let profile_count = profiles.len();
        let input_empty = persisted.input.is_empty();

        Self {
            input: persisted.input,
            profiles,
            subscriptions: Vec::new(),
            candidate_count: 0,
            unsupported_placeholders: 0,
            results: persisted.results,
            receiver: None,
            cancel_test: None,
            testing: false,
            total_tests: 0,
            completed_tests: 0,
            status: if profile_count > 0 {
                format!("Восстановлено серверов: {profile_count}")
            } else {
                "Вставьте подписку или список ссылок vless:// / hysteria2://".to_owned()
            },
            debug: if input_empty {
                "Диагностика: ввод пустой".to_owned()
            } else {
                "Диагностика: состояние восстановлено с прошлого запуска".to_owned()
            },
            favorites: persisted.favorites.into_iter().collect(),
            favorite_profiles: persisted.favorite_profiles,
            show_favorites_only: false,
            settings_open: false,
            statistics_open: false,
            stats_interval_minutes: persisted.stats_interval_minutes.max(1),
            stats_auto_enabled: false,
            stats_next_run: None,
            stats_history: persisted.stats_history,
            stats_resource_path: persisted.stats_resource_path,
            stats_status: "Статистика: ожидание".to_owned(),
            collect_stats_for_run: false,
            settings: persisted.settings,
        }
    }

    fn paste_from_clipboard(&mut self) {
        match Clipboard::new().and_then(|mut clipboard| clipboard.get_text()) {
            Ok(text) => {
                self.input = text;
                self.parse_input();
                if self.profiles.is_empty() && !self.subscriptions.is_empty() {
                    self.load_subscriptions();
                }
                self.save_state();
            }
            Err(error) => {
                self.status = format!("Не удалось прочитать буфер обмена: {error}");
            }
        }
    }

    fn parse_input(&mut self) {
        let output = parse_input(&self.input);
        self.profiles = output.profiles;
        self.merge_favorites_into_profiles();
        self.subscriptions = output.subscriptions;
        self.candidate_count = output.candidates;
        self.unsupported_placeholders = output.unsupported_placeholders;
        self.results.clear();
        self.completed_tests = 0;
        self.total_tests = 0;
        self.debug = format!(
            "Диагностика: символов {}, URL-кандидатов {}, профилей {}, подписок {}, unsupported-заглушек {}",
            self.input.chars().count(),
            self.candidate_count,
            self.profiles.len(),
            self.subscriptions.len(),
            self.unsupported_placeholders
        );
        self.status = if self.profiles.is_empty() {
            if self.subscriptions.is_empty() {
                "Серверы не найдены. Нужны vless://, hysteria2:// или HTTPS-подписка.".to_owned()
            } else {
                format!(
                    "Найдено подписок: {}. Нажмите \"Загрузить подписки\".",
                    self.subscriptions.len()
                )
            }
        } else {
            format!(
                "Найдено серверов: {}, подписок: {}",
                self.profiles.len(),
                self.subscriptions.len()
            )
        };
        self.save_state();
    }

    fn load_subscriptions(&mut self) {
        if self.subscriptions.is_empty() {
            self.status = "HTTPS-подписки не найдены.".to_owned();
            return;
        }

        let mut loaded = Vec::new();
        let mut errors = Vec::new();

        let mut reports = Vec::new();
        let mut unsupported_placeholders = 0;

        for source in &self.subscriptions {
            match load_subscription_detailed(source) {
                Ok(mut report) => {
                    unsupported_placeholders += report.unsupported_placeholders;
                    reports.push(format!(
                        "{} байт -> {} симв. -> {} проф., {} заглушек",
                        report.response_bytes,
                        report.decoded_chars,
                        report.profiles.len(),
                        report.unsupported_placeholders
                    ));
                    if report.profiles.is_empty() && report.unsupported_placeholders > 0 {
                        errors.push(format!(
                            "{}: подписка вернула заглушку \"Приложение не поддерживается\". Нужен Happ/Incy signed provider API request или экспорт профиля из приложения.",
                            source.url
                        ));
                    }
                    loaded.append(&mut report.profiles);
                }
                Err(error) => errors.push(error),
            }
        }

        for (id, profile) in loaded.iter_mut().enumerate() {
            profile.id = id;
        }

        self.merge_profiles(loaded);
        self.merge_favorites_into_profiles();
        self.unsupported_placeholders = unsupported_placeholders;
        self.results.clear();
        self.completed_tests = 0;
        self.total_tests = 0;
        self.status = if errors.is_empty() {
            format!("Подписки загружены. Серверов: {}", self.profiles.len())
        } else {
            format!(
                "Загружено серверов: {}. Ошибок подписок: {}",
                self.profiles.len(),
                errors.len()
            )
        };
        self.debug = if errors.is_empty() {
            format!(
                "Диагностика: загружено подписок {}, получено профилей {}, unsupported-заглушек {}. {}",
                self.subscriptions.len(),
                self.profiles.len(),
                self.unsupported_placeholders,
                reports.join("; ")
            )
        } else {
            format!(
                "Диагностика: загружено профилей {}, unsupported-заглушек {}, ошибок {}. Первая ошибка: {}",
                self.profiles.len(),
                self.unsupported_placeholders,
                errors.len(),
                errors.first().map_or("-", String::as_str)
            )
        };
        self.save_state();
    }

    fn merge_profiles(&mut self, loaded: Vec<Profile>) {
        let mut seen = self
            .profiles
            .iter()
            .map(|profile| profile.raw.clone())
            .collect::<HashSet<_>>();
        for mut profile in loaded {
            if seen.insert(profile.raw.clone()) {
                profile.id = self.profiles.len();
                self.profiles.push(profile);
            }
        }
    }

    fn select_all(&mut self, selected: bool) {
        for profile in &mut self.profiles {
            profile.selected = selected;
        }
        self.save_state();
    }

    fn start_test(&mut self) {
        let visible = self.visible_profile_ids();
        let selected_profiles = self
            .profiles
            .iter()
            .filter(|profile| visible.contains(&profile.id) && profile.selected)
            .cloned()
            .collect::<Vec<_>>();

        if selected_profiles.is_empty() {
            self.status = "Выберите хотя бы один сервер для теста.".to_owned();
            return;
        }

        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        tester::spawn_benchmark(
            selected_profiles,
            self.settings.clone(),
            Arc::clone(&cancel),
            sender,
        );
        self.receiver = Some(receiver);
        self.cancel_test = Some(cancel);
        self.testing = true;
        self.results.clear();
        self.completed_tests = 0;
        self.total_tests = 0;
        self.status = "Тестирование запущено через sing-box.".to_owned();
        self.collect_stats_for_run = true;
        self.save_state();
    }

    fn start_single_test(&mut self, profile_id: usize) {
        let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
        else {
            return;
        };

        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        tester::spawn_benchmark(
            vec![profile],
            self.settings.clone(),
            Arc::clone(&cancel),
            sender,
        );
        self.receiver = Some(receiver);
        self.cancel_test = Some(cancel);
        self.testing = true;
        self.results
            .retain(|result| result.profile_id != profile_id);
        self.completed_tests = 0;
        self.total_tests = 0;
        self.status = "Проверка выбранного сервера запущена.".to_owned();
        self.collect_stats_for_run = true;
        self.save_state();
    }

    fn stop_test(&mut self) {
        if let Some(cancel) = &self.cancel_test {
            cancel.store(true, Ordering::Relaxed);
        }
        self.status =
            "Остановка тестирования... текущая проверка завершится по таймауту.".to_owned();
    }

    fn poll_updates(&mut self, ctx: &egui::Context) {
        let Some(receiver) = self.receiver.take() else {
            return;
        };

        let mut keep_receiver = true;
        while let Ok(update) = receiver.try_recv() {
            match update {
                TestUpdate::Started { total } => {
                    self.total_tests = total;
                    self.completed_tests = 0;
                }
                TestUpdate::Running { profile_id } => {
                    self.results
                        .retain(|result| result.profile_id != profile_id);
                    self.results.push(TestResult {
                        profile_id,
                        latency_ms: 0,
                        jitter_ms: 0,
                        download_mbps: 0.0,
                        loss_percent: 0.0,
                        score: 0,
                        status: TestStatus::Running,
                    });
                }
                TestUpdate::Result(result) => {
                    self.completed_tests += 1;
                    self.results
                        .retain(|existing| existing.profile_id != result.profile_id);
                    if self.collect_stats_for_run {
                        self.record_stat_sample(&result);
                    }
                    self.results.push(result);
                    self.results.sort_by_key(|result| Reverse(result.score));
                    self.save_state();
                }
                TestUpdate::Finished => {
                    let stopped = self
                        .cancel_test
                        .as_ref()
                        .is_some_and(|cancel| cancel.load(Ordering::Relaxed));
                    self.testing = false;
                    self.cancel_test = None;
                    keep_receiver = false;
                    self.status = if stopped {
                        "Тестирование остановлено.".to_owned()
                    } else {
                        "Тестирование завершено. Лучшие серверы подняты вверх.".to_owned()
                    };
                    self.collect_stats_for_run = false;
                    self.save_state();
                }
            }
        }

        if keep_receiver {
            self.receiver = Some(receiver);
        }

        if self.testing {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn record_stat_sample(&mut self, result: &TestResult) {
        let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.id == result.profile_id)
        else {
            return;
        };
        self.stats_history.push(StatSample {
            timestamp: unix_now(),
            profile_raw: profile.raw.clone(),
            profile_name: profile.name.clone(),
            score: result.score,
            passed: matches!(result.status, TestStatus::Passed),
            latency_ms: result.latency_ms,
            download_mbps: result.download_mbps,
        });
        let max_samples = 5000;
        if self.stats_history.len() > max_samples {
            self.stats_history
                .drain(0..self.stats_history.len() - max_samples);
        }
    }

    fn result_for(&self, profile_id: usize) -> Option<&TestResult> {
        self.results
            .iter()
            .find(|result| result.profile_id == profile_id)
    }

    fn ordered_profile_ids(&self) -> Vec<usize> {
        let mut ids = self.visible_profile_ids();
        ids.sort_by(|left, right| {
            let left_profile = self.profiles.iter().find(|profile| profile.id == *left);
            let right_profile = self.profiles.iter().find(|profile| profile.id == *right);
            let left_score = self.result_for(*left).map_or(0, |result| result.score);
            let right_score = self.result_for(*right).map_or(0, |result| result.score);
            right_score.cmp(&left_score).then_with(|| {
                left_profile
                    .map(|profile| profile.name.as_str())
                    .cmp(&right_profile.map(|profile| profile.name.as_str()))
            })
        });
        ids
    }

    fn visible_profile_ids(&self) -> Vec<usize> {
        self.profiles
            .iter()
            .filter(|profile| !self.show_favorites_only || self.favorites.contains(&profile.raw))
            .map(|profile| profile.id)
            .collect()
    }

    fn toggle_favorite(&mut self, profile_id: usize) {
        let Some(raw) = self
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .map(|profile| profile.raw.clone())
        else {
            return;
        };

        if !self.favorites.insert(raw.clone()) {
            self.favorites.remove(&raw);
            self.favorite_profiles.retain(|profile| profile.raw != raw);
            if self.show_favorites_only {
                self.profiles
                    .retain(|profile| self.favorites.contains(&profile.raw));
                self.reassign_profile_ids();
            }
        } else if let Some(profile) = self
            .profiles
            .iter()
            .find(|profile| profile.raw == raw)
            .cloned()
            && !self
                .favorite_profiles
                .iter()
                .any(|favorite| favorite.raw == profile.raw)
        {
            self.favorite_profiles.push(profile);
        }
        self.save_state();
    }

    fn merge_favorites_into_profiles(&mut self) {
        merge_profiles_by_raw(&mut self.profiles, self.favorite_profiles.clone());
        self.reassign_profile_ids();
    }

    fn reassign_profile_ids(&mut self) {
        for (id, profile) in self.profiles.iter_mut().enumerate() {
            profile.id = id;
        }
    }

    fn save_state(&self) {
        let persisted = PersistedState {
            input: self.input.clone(),
            profiles: self.profiles.clone(),
            results: self.results.clone(),
            favorites: self.favorites.iter().cloned().collect(),
            favorite_profiles: self.favorite_profiles.clone(),
            stats_interval_minutes: self.stats_interval_minutes,
            stats_history: self.stats_history.clone(),
            stats_resource_path: self.stats_resource_path.clone(),
            settings: self.settings.clone(),
        };
        let Some(path) = state_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&persisted) {
            let _ = fs::write(path, text);
        }
    }

    fn has_errors(&self) -> bool {
        self.results
            .iter()
            .any(|result| matches!(result.status, TestStatus::Failed(_)))
    }

    fn copy_errors_to_clipboard(&mut self) {
        let errors = self.error_report();
        if errors.is_empty() {
            self.status = "Ошибок для копирования нет.".to_owned();
            return;
        }

        match Clipboard::new().and_then(|mut clipboard| clipboard.set_text(errors)) {
            Ok(()) => {
                self.status = "Ошибки скопированы в буфер обмена.".to_owned();
            }
            Err(error) => {
                self.status = format!("Не удалось скопировать ошибки: {error}");
            }
        }
    }

    fn error_report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("XrayVpnTest error report".to_owned());
        lines.push(format!(
            "profiles: {}, results: {}",
            self.profiles.len(),
            self.results.len()
        ));

        for result in &self.results {
            let TestStatus::Failed(error) = &result.status else {
                continue;
            };
            let profile = self
                .profiles
                .iter()
                .find(|profile| profile.id == result.profile_id);
            let name = profile.map_or("<unknown>", |profile| profile.name.as_str());
            let protocol = profile
                .map(|profile| profile.protocol.to_string())
                .unwrap_or_else(|| "<unknown>".to_owned());

            lines.push(format!(
                "\n[{id}] {name} ({protocol})\n{error}",
                id = result.profile_id
            ));
        }

        lines.join("\n")
    }
}

impl eframe::App for XrayVpnTestApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_updates(ctx);
        self.tick_stats_scheduler(ctx);

        egui::CentralPanel::default()
            .frame(Frame::default().fill(app_background()))
            .show(ctx, |ui| {
                ui.add_space(18.0);
                ui.horizontal(|ui| {
                    ui.add_space(22.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("XrayVpnTest")
                                .heading()
                                .strong()
                                .color(text_primary()),
                        );
                        ui.label(
                            RichText::new(
                                "Проверка VPN-узлов из подписок и share-links через sing-box",
                            )
                            .color(text_secondary()),
                        );
                    });
                });

                ui.add_space(14.0);
                self.render_command_bar(ui);
                self.render_settings_window(ctx);
                self.render_statistics_window(ctx);

                ui.add_space(14.0);
                let available_width = ui.available_width();
                let available_height = (ui.available_height() - 18.0).max(420.0);
                let gutter = 14.0;
                let outer_padding = 44.0;
                let input_width =
                    ((available_width - outer_padding - gutter) * 0.38).clamp(360.0, 520.0);
                let results_width =
                    (available_width - outer_padding - gutter - input_width).clamp(420.0, 1020.0);

                ui.horizontal_top(|ui| {
                    ui.add_space(22.0);
                    ui.set_height(available_height);
                    self.render_input_panel(ui, input_width, available_height);
                    ui.add_space(14.0);
                    self.render_results_panel(ui, results_width, available_height);
                });
            });
    }
}

impl XrayVpnTestApp {
    fn render_command_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add_space(22.0);
            Frame::default()
                .fill(command_bar_fill())
                .stroke(Stroke::new(1.0_f32, surface_border()))
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width((ui.available_width() - 44.0).max(700.0));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Вставить из буфера").clicked() {
                            self.paste_from_clipboard();
                        }
                        if ui
                            .add_enabled(
                                !self.testing && !self.subscriptions.is_empty(),
                                egui::Button::new("Загрузить подписки"),
                            )
                            .clicked()
                        {
                            self.load_subscriptions();
                        }

                        ui.separator();

                        if ui
                            .selectable_label(self.show_favorites_only, "Избранное")
                            .clicked()
                        {
                            self.show_favorites_only = !self.show_favorites_only;
                        }
                        if ui.button("Настройки").clicked() {
                            self.settings_open = true;
                        }
                        if ui.button("Статистика").clicked() {
                            self.statistics_open = true;
                        }

                        ui.separator();

                        if ui.button("Выбрать всё").clicked() {
                            self.select_all(true);
                        }
                        if ui.button("Снять выбор").clicked() {
                            self.select_all(false);
                        }
                        if ui
                            .add_enabled(!self.testing, egui::Button::new("Начать тест"))
                            .clicked()
                        {
                            self.start_test();
                        }
                        if ui
                            .add_enabled(self.testing, egui::Button::new("Стоп"))
                            .clicked()
                        {
                            self.stop_test();
                        }
                        if ui
                            .add_enabled(self.has_errors(), egui::Button::new("Копировать ошибки"))
                            .clicked()
                        {
                            self.copy_errors_to_clipboard();
                        }

                        if self.testing && self.total_tests > 0 {
                            ui.add_space(8.0);
                            let progress = self.completed_tests as f32 / self.total_tests as f32;
                            ui.add(
                                egui::ProgressBar::new(progress)
                                    .desired_width(180.0)
                                    .show_percentage(),
                            );
                        }
                    });
                });
        });
    }

    fn render_input_panel(&mut self, ui: &mut egui::Ui, width: f32, height: f32) {
        Frame::default()
            .fill(acrylic_fill())
            .stroke(Stroke::new(1.0_f32, surface_border()))
            .inner_margin(Margin::same(14))
            .corner_radius(2)
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.set_width(width);
                    ui.set_min_height(height);
                    ui.set_max_width(width);

                    ui.label(
                        RichText::new("Конфиг")
                            .size(20.0)
                            .strong()
                            .color(text_primary()),
                    );
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(&self.status)
                            .color(text_secondary())
                            .size(13.0),
                    );
                    ui.add_space(10.0);

                    Frame::default()
                        .fill(editor_fill())
                        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(55, 58, 64)))
                        .inner_margin(Margin::same(8))
                        .show(ui, |ui| {
                            let editor_height = (height - 190.0).max(240.0);
                            let response = ui.add_sized(
                                [width - 44.0, editor_height],
                                egui::TextEdit::multiline(&mut self.input)
                                    .hint_text("Вставьте HTTPS-подписку, vless:// или hysteria2://")
                                    .desired_width(f32::INFINITY)
                                    .code_editor(),
                            );
                            if response.changed() {
                                self.parse_input();
                            }
                        });

                    ui.add_space(10.0);
                    self.render_status_tiles(ui);
                    ui.add_space(8.0);
                    self.render_debug_line(ui);
                });
            });
    }

    fn render_debug_line(&self, ui: &mut egui::Ui) {
        Frame::default()
            .fill(Color32::from_rgba_unmultiplied(0, 120, 215, 22))
            .stroke(Stroke::new(
                1.0_f32,
                Color32::from_rgba_unmultiplied(0, 120, 215, 60),
            ))
            .inner_margin(Margin::symmetric(8, 6))
            .corner_radius(2)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(&self.debug)
                        .size(12.0)
                        .color(text_secondary()),
                );
            });
    }

    fn render_status_tiles(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            metric_tile(ui, "Серверы", self.profiles.len().to_string());
            metric_tile(ui, "Подписки", self.subscriptions.len().to_string());
            let selected = self
                .profiles
                .iter()
                .filter(|profile| profile.selected)
                .count();
            metric_tile(ui, "Выбрано", selected.to_string());
        });
    }

    fn render_results_panel(&mut self, ui: &mut egui::Ui, width: f32, height: f32) {
        Frame::default()
            .fill(content_fill())
            .stroke(Stroke::new(1.0_f32, surface_border()))
            .inner_margin(Margin::same(14))
            .corner_radius(2)
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.set_width(width);
                    ui.set_min_height(height);
                    ui.set_max_width(width);

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Серверы")
                                .size(20.0)
                                .strong()
                                .color(text_primary()),
                        );
                        ui.label(
                            RichText::new(format!(
                                "{} найдено, {} избранных",
                                self.profiles.len(),
                                self.favorites.len()
                            ))
                            .color(text_secondary())
                            .size(13.0),
                        );
                    });
                    ui.add_space(10.0);

                    if self.visible_profile_ids().is_empty() {
                        self.render_empty_state(ui, width, height - 80.0);
                    } else {
                        self.render_results_table(ui, height - 58.0);
                    }
                });
            });
    }

    fn render_empty_state(&self, ui: &mut egui::Ui, width: f32, height: f32) {
        Frame::default()
            .fill(Color32::from_rgb(18, 20, 23))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(42, 45, 50)))
            .inner_margin(Margin::same(18))
            .show(ui, |ui| {
                ui.set_min_size(egui::vec2((width - 44.0).max(300.0), height.max(260.0)));
                ui.vertical_centered(|ui| {
                    ui.add_space((height * 0.32).max(70.0));
                    ui.label(
                        RichText::new("Нет серверов")
                            .size(24.0)
                            .strong()
                            .color(text_primary()),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Вставьте подписку слева и нажмите “Загрузить подписки”.")
                            .color(text_secondary()),
                    );
                });
            });
    }

    fn render_results_table(&mut self, ui: &mut egui::Ui, height: f32) {
        let mut test_profile = None;
        let mut toggle_favorite = None;
        let mut selection_changed = false;
        Frame::default()
            .fill(Color32::from_rgb(18, 20, 23))
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(42, 45, 50)))
            .inner_margin(Margin::same(6))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_min_height(height.max(320.0));

                ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        TableBuilder::new(ui)
                            .striped(true)
                            .resizable(true)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(Column::exact(34.0))
                            .column(Column::exact(34.0))
                            .column(Column::initial(240.0).at_least(150.0))
                            .column(Column::initial(94.0).at_least(76.0))
                            .column(Column::initial(104.0).at_least(82.0))
                            .column(Column::initial(88.0).at_least(76.0))
                            .column(Column::initial(86.0).at_least(76.0))
                            .column(Column::initial(112.0).at_least(84.0))
                            .column(Column::initial(92.0).at_least(72.0))
                            .column(Column::initial(90.0).at_least(66.0))
                            .header(28.0, |mut header| {
                                for title in [
                                    "",
                                    "★",
                                    "Имя",
                                    "Протокол",
                                    "Транспорт",
                                    "Задержка",
                                    "Джиттер",
                                    "Скорость",
                                    "Потери",
                                    "Оценка",
                                ] {
                                    header.col(|ui| {
                                        ui.label(
                                            RichText::new(title).strong().color(text_secondary()),
                                        );
                                    });
                                }
                            })
                            .body(|body| {
                                let ordered_ids = self.ordered_profile_ids();
                                body.rows(34.0, ordered_ids.len(), |mut row| {
                                    let profile_id = ordered_ids[row.index()];
                                    let Some(profile_index) = self
                                        .profiles
                                        .iter()
                                        .position(|profile| profile.id == profile_id)
                                    else {
                                        return;
                                    };
                                    let profile_name = self.profiles[profile_index].name.clone();
                                    let protocol =
                                        self.profiles[profile_index].protocol.to_string();
                                    let transport = self.profiles[profile_index].transport();
                                    let raw = self.profiles[profile_index].raw.clone();
                                    let is_favorite = self.favorites.contains(&raw);
                                    let result = self.result_for(profile_id).cloned();

                                    row.col(|ui| {
                                        selection_changed |= ui
                                            .checkbox(
                                                &mut self.profiles[profile_index].selected,
                                                "",
                                            )
                                            .changed();
                                    });
                                    row.col(|ui| {
                                        if ui.button(if is_favorite { "★" } else { "☆" }).clicked()
                                        {
                                            toggle_favorite = Some(profile_id);
                                        }
                                    });
                                    row.col(|ui| {
                                        if result.as_ref().is_some_and(|result| {
                                            matches!(result.status, TestStatus::Running)
                                        }) {
                                            let rect = ui.max_rect().shrink2(egui::vec2(0.0, 3.0));
                                            ui.painter().rect_filled(
                                                rect,
                                                4.0,
                                                Color32::from_rgba_unmultiplied(0, 120, 215, 42),
                                            );
                                            ui.painter().circle_filled(
                                                rect.left_center() + egui::vec2(8.0, 0.0),
                                                5.0,
                                                Color32::from_rgb(96, 205, 255),
                                            );
                                        }
                                        let response = ui
                                            .label(RichText::new(profile_name).strong())
                                            .on_hover_text(raw);
                                        response.context_menu(|ui| {
                                            if ui.button("Проверить").clicked() {
                                                test_profile = Some(profile_id);
                                                ui.close();
                                            }
                                            if ui
                                                .button(if is_favorite {
                                                    "Убрать из избранного"
                                                } else {
                                                    "Добавить в избранное"
                                                })
                                                .clicked()
                                            {
                                                toggle_favorite = Some(profile_id);
                                                ui.close();
                                            }
                                        });
                                        ui.interact(
                                            ui.min_rect(),
                                            ui.id().with(profile_id),
                                            Sense::hover(),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.label(protocol);
                                    });
                                    row.col(|ui| {
                                        ui.label(transport);
                                    });
                                    row.col(|ui| {
                                        ui.label(metric_text(result.as_ref(), |value| {
                                            format!("{} ms", value.latency_ms)
                                        }));
                                    });
                                    row.col(|ui| {
                                        ui.label(metric_text(result.as_ref(), |value| {
                                            format!("{} ms", value.jitter_ms)
                                        }));
                                    });
                                    row.col(|ui| {
                                        ui.label(metric_text(result.as_ref(), |value| {
                                            format!("{:.1} Mbps", value.download_mbps)
                                        }));
                                    });
                                    row.col(|ui| {
                                        ui.label(metric_text(result.as_ref(), |value| {
                                            format!("{:.1}%", value.loss_percent)
                                        }));
                                    });
                                    row.col(|ui| {
                                        ui.label(score_text(result.as_ref()));
                                    });
                                });
                            });
                    });
            });
        if let Some(profile_id) = toggle_favorite {
            self.toggle_favorite(profile_id);
        }
        if selection_changed {
            self.save_state();
        }
        if let Some(profile_id) = test_profile {
            self.start_single_test(profile_id);
        }
    }

    fn render_settings_window(&mut self, ctx: &egui::Context) {
        if !self.settings_open {
            return;
        }

        let mut open = self.settings_open;
        let mut save = false;
        egui::Window::new("Настройки")
            .open(&mut open)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label("Адреса probe-запросов. По ним считается задержка и доступность.");
                save |= editable_url_list(ui, &mut self.settings.probe_urls);
                ui.add_space(12.0);
                ui.label("Адреса файлов для короткого теста скорости.");
                save |= editable_url_list(ui, &mut self.settings.download_urls);
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label("Время теста скорости, секунд");
                    save |= ui
                        .add(
                            egui::DragValue::new(&mut self.settings.download_seconds).range(1..=60),
                        )
                        .changed();
                });
                if ui.button("Вернуть адреса по умолчанию").clicked() {
                    self.settings = TestSettings::default();
                    save = true;
                }
            });
        self.settings_open = open;
        if save {
            self.save_state();
        }
    }

    fn render_statistics_window(&mut self, ctx: &egui::Context) {
        if !self.statistics_open {
            return;
        }

        let mut open = self.statistics_open;
        let mut save = false;
        egui::Window::new("Статистика")
            .open(&mut open)
            .resizable(true)
            .default_width(760.0)
            .default_height(620.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Интервал проверки, минут");
                    save |= ui
                        .add(egui::DragValue::new(&mut self.stats_interval_minutes).range(1..=1440))
                        .changed();
                    if ui
                        .button(if self.stats_auto_enabled {
                            "Остановить авто"
                        } else {
                            "Включить авто"
                        })
                        .clicked()
                    {
                        self.stats_auto_enabled = !self.stats_auto_enabled;
                        self.stats_next_run = if self.stats_auto_enabled {
                            Some(SystemTime::now())
                        } else {
                            None
                        };
                    }
                    if ui
                        .add_enabled(!self.testing, egui::Button::new("Проверить сейчас"))
                        .clicked()
                    {
                        self.start_test();
                        self.stats_status = "Статистика: проверка запущена вручную".to_owned();
                    }
                });

                ui.label(
                    RichText::new(
                        "Автоматизация проверяет серверы, отмеченные галочками в текущем списке.",
                    )
                    .color(text_secondary()),
                );
                ui.label(RichText::new(&self.stats_status).color(text_secondary()));
                ui.separator();

                ui.label("Тестируемые ресурсы задержки/доступности");
                save |= editable_url_list(ui, &mut self.settings.probe_urls);
                ui.horizontal(|ui| {
                    ui.label("Файл ресурсов");
                    save |= ui
                        .text_edit_singleline(&mut self.stats_resource_path)
                        .changed();
                    if ui.button("Загрузить").clicked() {
                        match fs::read_to_string(&self.stats_resource_path) {
                            Ok(text) => {
                                self.settings.probe_urls = text
                                    .lines()
                                    .map(str::trim)
                                    .filter(|line| !line.is_empty())
                                    .map(ToOwned::to_owned)
                                    .collect();
                                self.stats_status = format!(
                                    "Статистика: загружено ресурсов {}",
                                    self.settings.probe_urls.len()
                                );
                                save = true;
                            }
                            Err(error) => {
                                self.stats_status =
                                    format!("Не удалось загрузить ресурсы: {error}");
                            }
                        }
                    }
                    if ui.button("Экспорт").clicked() {
                        match fs::write(
                            &self.stats_resource_path,
                            self.settings.probe_urls.join("\n"),
                        ) {
                            Ok(()) => {
                                self.stats_status = "Статистика: ресурсы экспортированы".to_owned();
                            }
                            Err(error) => {
                                self.stats_status =
                                    format!("Не удалось экспортировать ресурсы: {error}");
                            }
                        }
                    }
                });

                ui.separator();
                ui.horizontal(|ui| {
                    metric_tile(ui, "Записей", self.stats_history.len().to_string());
                    metric_tile(ui, "Серверов", self.stats_server_count().to_string());
                    let stable = self
                        .stats_history
                        .iter()
                        .filter(|sample| sample.passed)
                        .count();
                    metric_tile(ui, "Успешных", stable.to_string());
                });
                ui.add_space(8.0);
                self.render_stats_graph(ui);
            });
        self.statistics_open = open;
        if save {
            self.save_state();
        }
    }

    fn render_stats_graph(&self, ui: &mut egui::Ui) {
        let desired = egui::vec2(ui.available_width().max(520.0), 300.0);
        let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, Color32::from_rgb(14, 16, 19));
        painter.rect_stroke(
            rect,
            4.0,
            Stroke::new(1.0_f32, Color32::from_rgb(50, 55, 64)),
            egui::StrokeKind::Outside,
        );

        if self.stats_history.is_empty() {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "История пока пустая",
                egui::FontId::proportional(16.0),
                text_secondary(),
            );
            return;
        }

        let samples = self
            .stats_history
            .iter()
            .rev()
            .take(120)
            .collect::<Vec<_>>();
        let graph = rect.shrink2(egui::vec2(18.0, 18.0));
        for line in 0..=4 {
            let y = graph.bottom() - graph.height() * line as f32 / 4.0;
            painter.line_segment(
                [egui::pos2(graph.left(), y), egui::pos2(graph.right(), y)],
                Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(255, 255, 255, 18)),
            );
        }

        let mut points = Vec::new();
        let count = samples.len().max(2) as f32;
        for (index, sample) in samples.iter().rev().enumerate() {
            let x = graph.left() + graph.width() * index as f32 / (count - 1.0);
            let y = graph.bottom() - graph.height() * sample.score as f32 / 100.0;
            points.push(egui::pos2(x, y));
            painter.circle_filled(
                egui::pos2(x, y),
                2.8,
                if sample.passed {
                    Color32::from_rgb(96, 205, 255)
                } else {
                    Color32::from_rgb(255, 111, 111)
                },
            );
        }
        painter.add(egui::Shape::line(
            points,
            Stroke::new(1.5_f32, Color32::from_rgb(0, 120, 215)),
        ));
    }

    fn stats_server_count(&self) -> usize {
        self.stats_history
            .iter()
            .map(|sample| sample.profile_raw.as_str())
            .collect::<HashSet<_>>()
            .len()
    }

    fn tick_stats_scheduler(&mut self, ctx: &egui::Context) {
        if !self.stats_auto_enabled || self.testing {
            return;
        }
        let now = SystemTime::now();
        if self.stats_next_run.is_none_or(|next| now >= next) {
            self.start_test();
            self.stats_status = "Статистика: автоматическая проверка запущена".to_owned();
            self.stats_next_run = Some(now + Duration::from_secs(self.stats_interval_minutes * 60));
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }
}

fn editable_url_list(ui: &mut egui::Ui, urls: &mut Vec<String>) -> bool {
    let mut changed = false;
    let mut remove = None;
    for (index, url) in urls.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            changed |= ui.text_edit_singleline(url).changed();
            if ui.button("-").clicked() {
                remove = Some(index);
            }
        });
    }
    if let Some(index) = remove {
        urls.remove(index);
        changed = true;
    }
    if ui.button("Добавить адрес").clicked() {
        urls.push("https://".to_owned());
        changed = true;
    }
    changed
}

fn load_persisted_state() -> PersistedState {
    let Some(path) = state_path() else {
        return PersistedState::default();
    };
    fs::read_to_string(&path)
        .ok()
        .or_else(|| old_state_path().and_then(|path| fs::read_to_string(path).ok()))
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn state_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/XrayVpnTest/state.json"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".config/xray-vpn-test/state.json"))
    }
}

fn old_state_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/Application Support/Incy Bench/state.json"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".config/incy-bench/state.json"))
    }
}

fn merge_profiles_by_raw(target: &mut Vec<Profile>, incoming: Vec<Profile>) {
    let mut seen = target
        .iter()
        .map(|profile| profile.raw.clone())
        .collect::<HashSet<_>>();
    for profile in incoming {
        if seen.insert(profile.raw.clone()) {
            target.push(profile);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn metric_tile(ui: &mut egui::Ui, label: &str, value: String) {
    Frame::default()
        .fill(Color32::from_rgba_unmultiplied(255, 255, 255, 12))
        .stroke(Stroke::new(
            1.0_f32,
            Color32::from_rgba_unmultiplied(255, 255, 255, 18),
        ))
        .inner_margin(Margin::symmetric(10, 8))
        .corner_radius(2)
        .show(ui, |ui| {
            ui.set_min_width(92.0);
            ui.label(
                RichText::new(value)
                    .size(20.0)
                    .strong()
                    .color(text_primary()),
            );
            ui.label(RichText::new(label).size(12.0).color(text_muted()));
        });
}

fn app_background() -> Color32 {
    Color32::from_rgb(12, 14, 17)
}

fn command_bar_fill() -> Color32 {
    Color32::from_rgb(24, 26, 30)
}

fn acrylic_fill() -> Color32 {
    Color32::from_rgba_unmultiplied(32, 36, 42, 238)
}

fn content_fill() -> Color32 {
    Color32::from_rgb(23, 25, 29)
}

fn editor_fill() -> Color32 {
    Color32::from_rgb(13, 15, 18)
}

fn surface_border() -> Color32 {
    Color32::from_rgb(57, 61, 68)
}

fn text_primary() -> Color32 {
    Color32::from_rgb(244, 246, 248)
}

fn text_secondary() -> Color32 {
    Color32::from_rgb(170, 180, 194)
}

fn text_muted() -> Color32 {
    Color32::from_rgb(120, 130, 145)
}

fn metric_text(result: Option<&TestResult>, format: impl FnOnce(&TestResult) -> String) -> String {
    match result {
        Some(value) if matches!(value.status, TestStatus::Passed) => format(value),
        Some(value) => match &value.status {
            TestStatus::Failed(reason) => reason.clone(),
            TestStatus::Pending => "ожидание".to_owned(),
            TestStatus::Running => "тест".to_owned(),
            TestStatus::Passed => String::new(),
        },
        None => "-".to_owned(),
    }
}

fn score_text(result: Option<&TestResult>) -> RichText {
    match result {
        Some(value) if matches!(value.status, TestStatus::Passed) => {
            let color = if value.score >= 75 {
                Color32::from_rgb(92, 220, 128)
            } else if value.score >= 45 {
                Color32::from_rgb(255, 196, 87)
            } else {
                Color32::from_rgb(255, 111, 111)
            };
            RichText::new(value.score.to_string()).strong().color(color)
        }
        Some(value) => match &value.status {
            TestStatus::Failed(_) => RichText::new("0").color(Color32::from_rgb(255, 111, 111)),
            TestStatus::Pending => RichText::new("-").color(Color32::GRAY),
            TestStatus::Running => RichText::new("...").color(Color32::GRAY),
            TestStatus::Passed => RichText::new("-"),
        },
        None => RichText::new("-").color(Color32::GRAY),
    }
}
