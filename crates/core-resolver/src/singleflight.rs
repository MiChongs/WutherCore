//! Singleflight: coalesce concurrent identical DNS queries.
//!
//! When multiple tasks request the same (host, qtype) simultaneously on a cache miss,
//! only one actual upstream query executes; the others await its result.

use std::{future::Future, hash::Hash, sync::Arc};

use dashmap::DashMap;
use tokio::sync::broadcast;

use crate::upstream::DnsError;

pub struct Singleflight<K: Eq + Hash + Clone> {
    flights: DashMap<K, Arc<FlightState>>,
}

struct FlightState {
    tx: broadcast::Sender<FlightResult>,
}

type FlightResult = Result<Vec<std::net::IpAddr>, Arc<DnsError>>;

struct FlightGuard<'a, K: Eq + Hash + Clone> {
    map: &'a DashMap<K, Arc<FlightState>>,
    key: K,
}

impl<K: Eq + Hash + Clone> Drop for FlightGuard<'_, K> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> Singleflight<K> {
    pub fn new() -> Self {
        Self {
            flights: DashMap::new(),
        }
    }

    pub async fn do_once<F, Fut>(
        &self,
        key: K,
        f: F,
    ) -> Result<Vec<std::net::IpAddr>, Arc<DnsError>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<std::net::IpAddr>, DnsError>>,
    {
        // Fast path: check if a flight is already in progress
        if let Some(entry) = self.flights.get(&key) {
            let mut rx = entry.tx.subscribe();
            drop(entry);
            return match rx.recv().await {
                Ok(result) => result,
                Err(_) => Err(Arc::new(DnsError::Failed(
                    "singleflight: sender dropped".into(),
                ))),
            };
        }

        // Try to become the owner of this flight
        let (tx, _) = broadcast::channel(1);
        let state = Arc::new(FlightState { tx: tx.clone() });

        let existing = self.flights.entry(key.clone()).or_insert(state.clone());
        if !Arc::ptr_eq(&*existing, &state) {
            // Another task won the race; subscribe to theirs
            let mut rx = existing.tx.subscribe();
            drop(existing);
            return match rx.recv().await {
                Ok(result) => result,
                Err(_) => Err(Arc::new(DnsError::Failed(
                    "singleflight: sender dropped".into(),
                ))),
            };
        }
        drop(existing);

        // We own this flight; execute the future
        let _guard = FlightGuard {
            map: &self.flights,
            key: key.clone(),
        };

        let result = f().await.map_err(Arc::new);
        // Broadcast to all waiters (ignore send errors — no receivers is fine)
        let _ = tx.send(result.clone());
        result
    }
}

impl<K: Eq + Hash + Clone + Send + Sync + 'static> Default for Singleflight<K> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::IpAddr,
        sync::atomic::{AtomicU32, Ordering},
        time::Duration,
    };

    use super::*;

    #[tokio::test]
    async fn single_execution() {
        let sf: Arc<Singleflight<String>> = Arc::new(Singleflight::new());
        let call_count = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let sf = sf.clone();
            let count = call_count.clone();
            handles.push(tokio::spawn(async move {
                sf.do_once("test.com".to_string(), || async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(vec!["1.2.3.4".parse::<IpAddr>().unwrap()])
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for r in &results {
            let ips = r.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(ips.len(), 1);
        }

        // Only one actual execution despite 10 concurrent requests
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn different_keys_run_independently() {
        let sf: Arc<Singleflight<String>> = Arc::new(Singleflight::new());
        let call_count = Arc::new(AtomicU32::new(0));

        let count1 = call_count.clone();
        let sf1 = sf.clone();
        let h1 = tokio::spawn(async move {
            sf1.do_once("a.com".to_string(), || async move {
                count1.fetch_add(1, Ordering::Relaxed);
                Ok(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])
            })
            .await
        });

        let count2 = call_count.clone();
        let sf2 = sf.clone();
        let h2 = tokio::spawn(async move {
            sf2.do_once("b.com".to_string(), || async move {
                count2.fetch_add(1, Ordering::Relaxed);
                Ok(vec!["2.2.2.2".parse::<IpAddr>().unwrap()])
            })
            .await
        });

        let (r1, r2) = tokio::join!(h1, h2);
        assert!(r1.unwrap().is_ok());
        assert!(r2.unwrap().is_ok());
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn error_propagates_to_waiters() {
        let sf: Arc<Singleflight<String>> = Arc::new(Singleflight::new());

        let mut handles = Vec::new();
        for _ in 0..5 {
            let sf = sf.clone();
            handles.push(tokio::spawn(async move {
                sf.do_once("fail.com".to_string(), || async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Err(DnsError::Timeout)
                })
                .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;
        for r in &results {
            assert!(r.as_ref().unwrap().is_err());
        }
    }

    #[tokio::test]
    async fn cleanup_after_completion() {
        let sf: Singleflight<String> = Singleflight::new();

        let _ = sf
            .do_once("cleanup.com".to_string(), || async {
                Ok(vec!["9.9.9.9".parse::<IpAddr>().unwrap()])
            })
            .await;

        // Entry should be removed after completion
        assert!(sf.flights.is_empty());
    }
}
