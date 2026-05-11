//! Shared width and truncation helpers for the live TUI.
//!
//! Ratatui tables need stable explicit widths. These helpers keep sizing rules
//! deterministic so refreshed rows do not resize or shift the interface while a
//! scan is running.

pub(super) const TABLE_COLUMN_SPACING: u16 = 2;

pub(super) fn fit_cell(value: String, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value;
    }
    if max_chars == 0 {
        return String::new();
    }
    if max_chars <= 1 {
        return "~".to_string();
    }
    let mut fitted = value.chars().take(max_chars - 1).collect::<String>();
    fitted.push('~');
    fitted
}

pub(super) fn corrected_table_offset(
    selected: usize,
    current_offset: usize,
    visible_rows: usize,
) -> usize {
    let visible_rows = visible_rows.max(1);
    if selected < current_offset {
        selected
    } else if selected >= current_offset.saturating_add(visible_rows) {
        selected.saturating_sub(visible_rows - 1)
    } else {
        current_offset
    }
}

pub(super) fn spread_width(total: u16, columns: usize) -> Vec<u16> {
    if columns == 0 {
        return Vec::new();
    }
    let columns = columns.try_into().unwrap_or(u16::MAX);
    let base = total.checked_div(columns).unwrap_or(0);
    let mut remainder = total.checked_rem(columns).unwrap_or(0);
    (0..columns)
        .map(|_| {
            let extra = u16::from(remainder > 0);
            remainder = remainder.saturating_sub(1);
            base + extra
        })
        .collect()
}

pub(super) fn shrink_widths_to_fit(widths: &mut [u16], minimums: Vec<u16>, total: u16) {
    let current = widths.iter().copied().sum::<u16>();
    if current <= total {
        return;
    }

    let mut overflow = current - total;
    // Trim one cell at a time across columns so no single flexible column takes
    // the whole penalty unless the others have already reached their minimums.
    while overflow > 0 {
        let mut changed = false;
        for (width, minimum) in widths.iter_mut().zip(minimums.iter()) {
            if overflow == 0 {
                break;
            }
            if *width > *minimum {
                *width -= 1;
                overflow -= 1;
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    if overflow > 0 {
        let fitted_widths = spread_width(total, widths.len());
        for (width, fitted) in widths.iter_mut().zip(fitted_widths) {
            *width = fitted;
        }
    }
}

pub(super) fn table_spacing_width(column_count: usize) -> u16 {
    column_count
        .saturating_sub(1)
        .try_into()
        .unwrap_or(u16::MAX)
        .saturating_mul(TABLE_COLUMN_SPACING)
}
