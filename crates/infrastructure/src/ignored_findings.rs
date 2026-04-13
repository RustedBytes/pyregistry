#[derive(Debug, Clone, Default)]
pub(crate) struct IgnoredFindings {
    values: Vec<String>,
}

impl IgnoredFindings {
    pub(crate) fn new(values: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            values: values
                .into_iter()
                .map(|value| normalize_ignore_value(value.as_ref()))
                .filter(|value| !value.is_empty())
                .collect(),
        }
    }

    pub(crate) fn matches(&self, value: &str) -> bool {
        let value = normalize_ignore_value(value);
        self.values.iter().any(|ignored| ignored == &value)
    }
}

fn normalize_ignore_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_are_trimmed_and_case_insensitive() {
        let ignores = IgnoredFindings::new([" GHSA-DEMO ", "", "foxguard/rule"]);

        assert!(ignores.matches("ghsa-demo"));
        assert!(ignores.matches("FOXGUARD/RULE"));
        assert!(!ignores.matches("other"));
    }
}
