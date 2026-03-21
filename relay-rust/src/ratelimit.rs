use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

pub struct Limiter {
    inner: Mutex<LimiterInner>,
}

struct LimiterInner {
    per_second: f64,
    burst: f64,
    entries: HashMap<IpAddr, LimitEntry>,
}

struct LimitEntry {
    tokens: f64,
    last: Instant,
}

impl Limiter {
    pub fn new(per_second: u32, burst: u32) -> Self {
        Self {
            inner: Mutex::new(LimiterInner {
                per_second: per_second as f64,
                burst: burst as f64,
                entries: HashMap::new(),
            }),
        }
    }

    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let per_second = inner.per_second;
        let burst = inner.burst;
        match inner.entries.get_mut(&ip) {
            Some(entry) => {
                let elapsed = now.duration_since(entry.last).as_secs_f64();
                entry.tokens = (entry.tokens + elapsed * per_second).min(burst);
                entry.last = now;
                if entry.tokens < 1.0 {
                    return false;
                }
                entry.tokens -= 1.0;
                true
            }
            None => {
                inner.entries.insert(
                    ip,
                    LimitEntry {
                        tokens: (burst - 1.0).max(0.0),
                        last: now,
                    },
                );
                true
            }
        }
    }

    pub fn cleanup(&self, before: Instant) {
        let mut inner = self.inner.lock().unwrap();
        inner.entries.retain(|_, entry| entry.last >= before);
    }
}
