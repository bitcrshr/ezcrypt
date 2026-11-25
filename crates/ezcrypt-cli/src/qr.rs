use anyhow::{Context, Result};
use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

/// Renders `url` as half-block characters, black on white, so it scans in
/// light and dark terminals alike and stays within 80 columns.
pub fn render(url: &str) -> Result<String> {
    let code = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::L)
        .context("the link is too long for a QR code")?;
    let text = code
        .render::<Dense1x2>()
        .quiet_zone(true)
        .module_dimensions(1, 1)
        .build();
    Ok(text
        .lines()
        .map(|line| format!("\x1b[30;47m{line}\x1b[0m"))
        .collect::<Vec<_>>()
        .join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    #[test]
    fn fits_eighty_columns() {
        let url = format!("ezcrypt://enroll?{}", "a1b2c3d4".repeat(40));
        assert!(url.len() >= 300);
        let rendered = render(&url).unwrap();
        let plain = strip_ansi(&rendered);
        assert!(plain.lines().count() > 10);
        for line in plain.lines() {
            assert!(
                line.chars().count() <= 80,
                "{} columns",
                line.chars().count()
            );
        }
    }
}
