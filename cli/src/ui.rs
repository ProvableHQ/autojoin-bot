use std::{env, io::IsTerminal};

fn enabled() -> bool {
    env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn paint(code: &str, text: &str) -> String {
    if enabled() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

pub fn heading(text: &str) -> String {
    paint("1;36", text)
}

pub fn prompt(text: &str) -> String {
    paint("36", text)
}

pub fn success(text: &str) -> String {
    paint("32", text)
}

pub fn warning(text: &str) -> String {
    paint("33", text)
}

pub fn muted(text: &str) -> String {
    paint("2", text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirected_output_has_no_escape_sequences() {
        if !std::io::stdout().is_terminal() {
            assert_eq!(heading("Setup"), "Setup");
        }
    }
}
