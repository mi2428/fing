//! Live device table columns, row rendering, and in-place device merging.
//!
//! The live table receives partial snapshots from successive scan phases. This
//! module keeps row rendering close to the merge policy that protects enriched
//! identity from being erased by later, weaker refreshes.

use super::{
    layout::{fit_cell, spread_width, table_spacing_width},
    theme::NeonTheme,
};
use crate::model::{Device, Guess};
use ratatui::{
    layout::Constraint,
    style::Style,
    widgets::{Cell as TuiCell, Row as TuiRow},
};
use std::net::IpAddr;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct DeviceKey {
    pub(super) interface: String,
    pub(super) ip: IpAddr,
}

impl DeviceKey {
    pub(super) fn from_device(device: &Device) -> Self {
        Self {
            interface: device.interface.clone().unwrap_or_default(),
            ip: device.ip,
        }
    }
}

pub(super) fn device_matches_search(device: &Device, query: &str) -> bool {
    // Search follows the operator's mental model: match any visible identity
    // field, not just the current hostname column.
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }

    search_values(device)
        .into_iter()
        .any(|value| value.to_lowercase().contains(&needle))
}

fn search_values(device: &Device) -> Vec<String> {
    let mut values = vec![device.ip.to_string()];
    values.extend(device.mac.iter().cloned());
    values.extend(device.vendor.iter().cloned());
    values.extend(device.model.as_ref().map(|guess| guess.value.clone()));
    values.extend(device.hostname.iter().cloned());
    values.extend(device.names.iter().map(|name| name.name.clone()));
    values.extend(device.os.as_ref().map(|guess| guess.value.clone()));
    values
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeviceColumn {
    Ip,
    Interface,
    Mac,
    Vendor,
    Model,
    Name,
    Os,
    Confidence,
    Sources,
    Seen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DeviceTableColumn {
    pub(super) kind: DeviceColumn,
    pub(super) width: u16,
}

impl DeviceTableColumn {
    pub(super) fn title(self) -> &'static str {
        self.kind.title()
    }

    pub(super) fn constraint(self) -> Constraint {
        Constraint::Length(self.width)
    }

    pub(super) fn max_chars(self) -> usize {
        self.width as usize
    }

    pub(super) fn value(self, device: &Device, options: super::super::OutputOptions) -> String {
        self.kind.value(device, options)
    }
}

impl DeviceColumn {
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Ip => "IP",
            Self::Interface => "Iface",
            Self::Mac => "MAC",
            Self::Vendor => "Vendor",
            Self::Model => "Model",
            Self::Name => "Name",
            Self::Os => "OS",
            Self::Confidence => "Conf",
            Self::Sources => "Sources",
            Self::Seen => "Seen",
        }
    }

    pub(super) fn fixed_width(self) -> Option<u16> {
        match self {
            Self::Ip => Some(15),
            Self::Interface => Some(8),
            Self::Mac => Some(17),
            Self::Vendor | Self::Model | Self::Name | Self::Os => None,
            Self::Confidence => Some(6),
            // Sources is intentionally fixed and compact. It uses one-letter
            // evidence codes like AO for arp+oui so it does not steal width from
            // higher-value identity columns.
            Self::Sources => Some(10),
            Self::Seen => Some(8),
        }
    }

    pub(super) fn is_elastic(self) -> bool {
        matches!(self, Self::Vendor | Self::Model | Self::Name | Self::Os)
    }

    pub(super) fn value(self, device: &Device, options: super::super::OutputOptions) -> String {
        match self {
            Self::Ip => device.ip.to_string(),
            Self::Interface => device.interface.as_deref().unwrap_or("-").to_string(),
            Self::Mac => super::super::privacy::display_mac(device.mac.as_deref(), options),
            Self::Vendor => device.vendor.as_deref().unwrap_or("-").to_string(),
            Self::Model => device
                .model
                .as_ref()
                .map(|guess| guess.value.as_str())
                .unwrap_or("-")
                .to_string(),
            Self::Name => device.hostname.as_deref().unwrap_or("-").to_string(),
            Self::Os => device
                .os
                .as_ref()
                .map(|guess| guess.value.as_str())
                .unwrap_or("-")
                .to_string(),
            Self::Confidence => format!("{:.2}", device.identity_confidence()),
            Self::Sources => super::super::sources::compact_source_summary(device),
            Self::Seen => device.last_seen.format("%H:%M:%S").to_string(),
        }
    }
}

#[cfg(test)]
pub(super) fn visible_columns(width: u16) -> Vec<DeviceTableColumn> {
    let kinds = visible_column_kinds(width);
    allocate_device_columns(width, &kinds)
}

pub(super) fn visible_columns_for_devices(
    width: u16,
    devices: &[&Device],
    options: super::super::OutputOptions,
) -> Vec<DeviceTableColumn> {
    let kinds = visible_column_kinds(width);
    allocate_device_columns_for_devices(width, &kinds, devices, options)
}

fn visible_column_kinds(width: u16) -> Vec<DeviceColumn> {
    if width < 96 {
        vec![
            DeviceColumn::Ip,
            DeviceColumn::Interface,
            DeviceColumn::Name,
            DeviceColumn::Os,
            DeviceColumn::Confidence,
            DeviceColumn::Sources,
        ]
    } else if width < 150 {
        vec![
            DeviceColumn::Ip,
            DeviceColumn::Interface,
            DeviceColumn::Mac,
            DeviceColumn::Vendor,
            DeviceColumn::Name,
            DeviceColumn::Os,
            DeviceColumn::Confidence,
            DeviceColumn::Sources,
        ]
    } else {
        vec![
            DeviceColumn::Ip,
            DeviceColumn::Interface,
            DeviceColumn::Mac,
            DeviceColumn::Vendor,
            DeviceColumn::Model,
            DeviceColumn::Name,
            DeviceColumn::Os,
            DeviceColumn::Confidence,
            DeviceColumn::Sources,
            DeviceColumn::Seen,
        ]
    }
}

#[cfg(test)]
fn allocate_device_columns(width: u16, kinds: &[DeviceColumn]) -> Vec<DeviceTableColumn> {
    let inner_width = width
        .saturating_sub(2)
        .saturating_sub(table_spacing_width(kinds.len()));
    let fixed_total = kinds
        .iter()
        .filter_map(|column| column.fixed_width())
        .sum::<u16>();
    let elastic_count = kinds.iter().filter(|column| column.is_elastic()).count() as u16;
    let elastic_total = inner_width.saturating_sub(fixed_total);
    let elastic_base = elastic_total.checked_div(elastic_count).unwrap_or(0);
    let mut elastic_remainder = elastic_total.checked_rem(elastic_count).unwrap_or(0);

    kinds
        .iter()
        .map(|kind| {
            let width = if let Some(width) = kind.fixed_width() {
                width
            } else {
                let extra = u16::from(elastic_remainder > 0);
                elastic_remainder = elastic_remainder.saturating_sub(1);
                // Four characters is enough to show a useful prefix plus '~'.
                // On normal terminals this will be much larger because the
                // fixed columns are kept deliberately small.
                (elastic_base + extra).max(4)
            };
            DeviceTableColumn { kind: *kind, width }
        })
        .collect()
}

fn allocate_device_columns_for_devices(
    width: u16,
    kinds: &[DeviceColumn],
    devices: &[&Device],
    options: super::super::OutputOptions,
) -> Vec<DeviceTableColumn> {
    let inner_width = width
        .saturating_sub(2)
        .saturating_sub(table_spacing_width(kinds.len()));
    let fixed_total = kinds
        .iter()
        .filter_map(|column| column.fixed_width())
        .sum::<u16>();
    let elastic_total = inner_width.saturating_sub(fixed_total);
    let elastic_kinds = kinds
        .iter()
        .copied()
        .filter(|kind| kind.is_elastic())
        .collect::<Vec<_>>();
    let elastic_widths =
        allocate_elastic_device_widths(elastic_total, &elastic_kinds, devices, options);
    let mut elastic_index = 0;

    kinds
        .iter()
        .map(|kind| {
            let width = if let Some(width) = kind.fixed_width() {
                width
            } else {
                let width = elastic_widths.get(elastic_index).copied().unwrap_or(4);
                elastic_index += 1;
                width
            };
            DeviceTableColumn { kind: *kind, width }
        })
        .collect()
}

fn allocate_elastic_device_widths(
    total: u16,
    kinds: &[DeviceColumn],
    devices: &[&Device],
    options: super::super::OutputOptions,
) -> Vec<u16> {
    if kinds.is_empty() {
        return Vec::new();
    }

    let desired = kinds
        .iter()
        .map(|kind| desired_device_column_width(*kind, devices, options))
        .collect::<Vec<_>>();
    let minimum = kinds
        .iter()
        .map(|kind| ((*kind).title().chars().count() as u16).max(4))
        .collect::<Vec<_>>();
    let minimum_total = minimum.iter().copied().sum::<u16>();
    if total <= minimum_total {
        return spread_width(total, kinds.len());
    }

    // Give each elastic column its header-sized minimum first, then feed extra
    // width toward columns that have actual content to display before spreading
    // any leftover space evenly.
    let mut widths = minimum;
    let mut remaining = total - minimum_total;

    while remaining > 0 {
        let receivers = widths
            .iter()
            .zip(desired.iter())
            .enumerate()
            .filter_map(|(index, (width, desired))| (*width < *desired).then_some(index))
            .collect::<Vec<_>>();
        if receivers.is_empty() {
            break;
        }
        for index in receivers {
            if remaining == 0 {
                break;
            }
            widths[index] += 1;
            remaining -= 1;
        }
    }

    let mut index = 0;
    while remaining > 0 {
        widths[index] += 1;
        remaining -= 1;
        index = (index + 1) % widths.len();
    }

    widths
}

fn desired_device_column_width(
    kind: DeviceColumn,
    devices: &[&Device],
    options: super::super::OutputOptions,
) -> u16 {
    let title_width = kind.title().chars().count();
    let value_width = devices
        .iter()
        .map(|device| kind.value(device, options).chars().count())
        .max()
        .unwrap_or(0);
    title_width.max(value_width).try_into().unwrap_or(u16::MAX)
}

pub(super) fn device_row(
    device: &Device,
    columns: &[DeviceTableColumn],
    options: super::super::OutputOptions,
) -> TuiRow<'static> {
    let style = device_row_style(device);

    TuiRow::new(
        columns
            .iter()
            .map(|column| {
                TuiCell::from(fit_cell(column.value(device, options), column.max_chars()))
            })
            .collect::<Vec<_>>(),
    )
    .style(style)
}

pub(super) fn device_row_style(device: &Device) -> Style {
    if device.hostname.is_some()
        || device.make.is_some()
        || device.model.is_some()
        || device.os.is_some()
        || device.device_type.is_some()
    {
        Style::default()
            .fg(NeonTheme::TEXT)
            .bg(NeonTheme::BACKGROUND)
    } else if device.vendor.is_some() {
        // OUI-only identity is useful but weak; show it as bright orange, not
        // green, because it is still table data rather than UI emphasis.
        Style::default()
            .fg(NeonTheme::PRIMARY_SOFT)
            .bg(NeonTheme::BACKGROUND)
    } else {
        Style::default()
            .fg(NeonTheme::DIM)
            .bg(NeonTheme::BACKGROUND)
    }
}

pub(super) fn live_identity_signature(device: &Device) -> String {
    // Last Seen is intentionally omitted. Continuous scanning should refresh
    // table cells without flooding the live log when a host is merely observed again.
    format!(
        "mac={:?}|vendor={:?}|name={:?}|make={}|model={}|os={}|type={}|services={}|evidence={}|sources={}|confidence={:.2}",
        device.mac,
        device.vendor,
        device.hostname,
        guess_value(&device.make),
        guess_value(&device.model),
        guess_value(&device.os),
        guess_value(&device.device_type),
        device.services.len(),
        device.evidence.len(),
        super::super::sources::source_summary(device),
        device.identity_confidence(),
    )
}

pub(super) fn device_log_summary(device: &Device, options: super::super::OutputOptions) -> String {
    format!(
        "ip={} iface={} mac={} vendor={} model={} name={} os={} conf={:.2} sources={} seen={} svc={} ev={}",
        device.ip,
        device.interface.as_deref().unwrap_or("-"),
        log_field_value(
            &super::super::privacy::display_mac(device.mac.as_deref(), options),
            17
        ),
        log_optional_value(device.vendor.as_deref(), 24),
        log_field_value(guess_value(&device.model), 20),
        log_optional_value(device.hostname.as_deref(), 24),
        log_field_value(guess_value(&device.os), 20),
        device.identity_confidence(),
        super::super::sources::compact_source_summary(device),
        device.last_seen.format("%H:%M:%S"),
        device.services.len(),
        device.evidence.len(),
    )
}

fn log_optional_value(value: Option<&str>, max_chars: usize) -> String {
    log_field_value(value.unwrap_or("-"), max_chars)
}

fn log_field_value(value: &str, max_chars: usize) -> String {
    let compact = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("_")
        .replace(',', ";");
    fit_cell(compact, max_chars)
}

fn guess_value(guess: &Option<Guess>) -> &str {
    guess
        .as_ref()
        .map(|guess| guess.value.as_str())
        .unwrap_or("-")
}

pub(super) fn merge_live_device(existing: &mut Device, mut incoming: Device) {
    // Live events are snapshots at different enrichment depths, not authoritative
    // replacements. This matters most in continuous mode: the next round starts again
    // with ARP/OUI evidence, and replacing the row would briefly erase hostnames,
    // OS hints, services, and protocol evidence learned by the previous round.
    if existing.interface.is_none() {
        existing.interface = incoming.interface.take();
    }
    if existing.mac.is_none() {
        existing.mac = incoming.mac.take();
    }
    if existing.vendor.is_none() {
        existing.vendor = incoming.vendor.take();
    }
    if existing.hostname.is_none() {
        existing.hostname = incoming.hostname.take();
    }
    for name in incoming.names {
        existing.add_name(name.name, &name.source, name.confidence);
    }
    if let Some(make) = incoming.make {
        existing.set_make_guess(make.value, &make.source, make.confidence);
    }
    if let Some(model) = incoming.model {
        existing.set_model_guess(model.value, &model.source, model.confidence);
    }
    if let Some(os) = incoming.os {
        existing.set_os_guess(os.value, &os.source, os.confidence);
    }
    if let Some(device_type) = incoming.device_type {
        existing.set_device_type_guess(
            device_type.value,
            &device_type.source,
            device_type.confidence,
        );
    }
    for service in incoming.services {
        existing.add_service(
            service.name,
            &service.source,
            service.port,
            service.confidence,
        );
    }
    for evidence in incoming.evidence {
        existing.add_evidence(
            &evidence.source,
            &evidence.key,
            evidence.value,
            evidence.confidence,
        );
    }
    existing.first_seen = existing.first_seen.min(incoming.first_seen);
    existing.last_seen = existing.last_seen.max(incoming.last_seen);
}
