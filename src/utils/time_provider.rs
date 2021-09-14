use chrono::{DateTime, Utc};

///
/// An overridable clock - used for tests.
///
#[derive(Debug)]
pub struct TimeProvider {
    fixed: Option<DateTime<Utc>>
}

impl TimeProvider {
    pub fn default() -> Self {
        TimeProvider { fixed: None }
    }

    pub fn now(&self) -> DateTime<Utc> {
        match self.fixed {
            Some(fixed) => fixed,
            None => Utc::now()
        }
    }

    pub fn fix(&mut self, fixed: Option<DateTime<Utc>>) {
        self.fixed = fixed;
    }
}