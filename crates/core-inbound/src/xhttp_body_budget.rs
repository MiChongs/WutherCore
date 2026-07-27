//! Listener-wide byte reservations for finite XHTTP packet request bodies.

use std::{future::Future, io, sync::Arc};

use bytes::Bytes;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub(crate) struct PacketBodyBudget {
    normal: Arc<Semaphore>,
    priority: Arc<Semaphore>,
    reservation_bytes: u32,
}

impl PacketBodyBudget {
    pub(crate) fn new(reservation_bytes: usize, normal_posts: usize) -> io::Result<Self> {
        if reservation_bytes == 0 {
            return Err(invalid_input(
                "XHTTP packet body reservation must be greater than zero",
            ));
        }
        if normal_posts == 0 {
            return Err(invalid_input(
                "XHTTP packet body normal post count must be greater than zero",
            ));
        }
        let normal_capacity = reservation_bytes
            .checked_mul(normal_posts)
            .ok_or_else(|| invalid_input("XHTTP packet body normal budget capacity overflowed"))?;
        if normal_capacity > Semaphore::MAX_PERMITS {
            return Err(invalid_input(format!(
                "XHTTP packet body normal budget exceeds semaphore limit {}",
                Semaphore::MAX_PERMITS
            )));
        }
        if reservation_bytes > Semaphore::MAX_PERMITS {
            return Err(invalid_input(format!(
                "XHTTP packet body priority budget exceeds semaphore limit {}",
                Semaphore::MAX_PERMITS
            )));
        }
        let reservation_bytes = u32::try_from(reservation_bytes).map_err(|_| {
            invalid_input("XHTTP packet body reservation exceeds owned semaphore acquire limit")
        })?;
        Ok(Self {
            normal: Arc::new(Semaphore::new(normal_capacity)),
            priority: Arc::new(Semaphore::new(reservation_bytes as usize)),
            reservation_bytes,
        })
    }

    /// Reserve one maximum-sized body from the ordinary listener-wide pool.
    ///
    /// Timeout policy belongs to the HTTP caller. `cancelled` may combine the
    /// listener and session cancellation futures.
    pub(crate) async fn acquire_normal<C>(&self, cancelled: C) -> io::Result<PacketBodyPermit>
    where
        C: Future<Output = ()>,
    {
        self.acquire_from(Arc::clone(&self.normal), cancelled).await
    }

    /// Reserve one maximum-sized body from the next-sequence priority pool.
    pub(crate) async fn acquire_priority<C>(&self, cancelled: C) -> io::Result<PacketBodyPermit>
    where
        C: Future<Output = ()>,
    {
        self.acquire_from(Arc::clone(&self.priority), cancelled)
            .await
    }

    async fn acquire_from<C>(
        &self,
        semaphore: Arc<Semaphore>,
        cancelled: C,
    ) -> io::Result<PacketBodyPermit>
    where
        C: Future<Output = ()>,
    {
        let permit = tokio::select! {
            biased;
            _ = cancelled => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "XHTTP packet body budget acquisition cancelled",
                ));
            }
            permit = semaphore.acquire_many_owned(self.reservation_bytes) => {
                permit.map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "XHTTP packet body budget is closed",
                    )
                })?
            }
        };
        Ok(PacketBodyPermit {
            permit: Some(permit),
            reserved: self.reservation_bytes as usize,
        })
    }
}

#[derive(Debug)]
pub(crate) struct PacketBodyPermit {
    permit: Option<OwnedSemaphorePermit>,
    reserved: usize,
}

impl PacketBodyPermit {
    /// Attach the used portion of this reservation to the returned bytes.
    ///
    /// Unused permits are returned immediately. The used permits remain owned
    /// by the backing allocation until the final `Bytes` clone is dropped.
    pub(crate) fn attach(mut self, payload: Vec<u8>) -> io::Result<Bytes> {
        if payload.len() > self.reserved {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "XHTTP packet body has {} bytes but only {} were reserved",
                    payload.len(),
                    self.reserved
                ),
            ));
        }
        let mut permit = self
            .permit
            .take()
            .expect("packet body permit can only be attached once");
        if payload.is_empty() {
            drop(permit);
            return Ok(Bytes::new());
        }
        let unused = self.reserved - payload.len();
        if unused > 0 {
            let unused_permit = permit
                .split(unused)
                .expect("unused permit count is bounded by the reservation");
            drop(unused_permit);
        }
        Ok(Bytes::from_owner(PermittedPayload {
            data: payload,
            _permit: permit,
        }))
    }
}

#[derive(Debug)]
struct PermittedPayload {
    data: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for PermittedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};

    use super::*;

    #[test]
    fn rejects_invalid_capacities() {
        assert_eq!(
            PacketBodyBudget::new(0, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            PacketBodyBudget::new(1, 0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            PacketBodyBudget::new(usize::MAX, 2).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            PacketBodyBudget::new(Semaphore::MAX_PERMITS + 1, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn normal_and_priority_capacities_are_isolated() {
        let budget = PacketBodyBudget::new(4, 1).unwrap();
        let normal = budget.acquire_normal(pending()).await.unwrap();
        assert_eq!(budget.normal.available_permits(), 0);
        assert_eq!(budget.priority.available_permits(), 4);

        let priority = budget.acquire_priority(pending()).await.unwrap();
        assert_eq!(budget.normal.available_permits(), 0);
        assert_eq!(budget.priority.available_permits(), 0);

        drop(normal);
        assert_eq!(budget.normal.available_permits(), 4);
        assert_eq!(budget.priority.available_permits(), 0);
        drop(priority);
        assert_eq!(budget.priority.available_permits(), 4);
    }

    #[tokio::test]
    async fn dropping_unattached_permit_returns_full_reservation() {
        let budget = PacketBodyBudget::new(8, 1).unwrap();
        let permit = budget.acquire_normal(pending()).await.unwrap();
        assert_eq!(budget.normal.available_permits(), 0);
        drop(permit);
        assert_eq!(budget.normal.available_permits(), 8);
    }

    #[tokio::test]
    async fn attach_returns_unused_capacity_immediately() {
        let budget = PacketBodyBudget::new(8, 1).unwrap();
        let permit = budget.acquire_normal(pending()).await.unwrap();
        let bytes = permit.attach(vec![1, 2, 3]).unwrap();
        assert_eq!(&bytes[..], &[1, 2, 3]);
        assert_eq!(budget.normal.available_permits(), 5);
        drop(bytes);
        assert_eq!(budget.normal.available_permits(), 8);
    }

    #[tokio::test]
    async fn final_bytes_clone_owns_used_capacity() {
        let budget = PacketBodyBudget::new(4, 1).unwrap();
        let permit = budget.acquire_normal(pending()).await.unwrap();
        let bytes = permit.attach(vec![1, 2, 3, 4]).unwrap();
        let clone = bytes.clone();
        assert_eq!(budget.normal.available_permits(), 0);
        drop(bytes);
        assert_eq!(budget.normal.available_permits(), 0);
        drop(clone);
        assert_eq!(budget.normal.available_permits(), 4);
    }

    #[tokio::test]
    async fn overlong_payload_is_rejected_and_releases_reservation() {
        let budget = PacketBodyBudget::new(4, 1).unwrap();
        let permit = budget.acquire_normal(pending()).await.unwrap();
        let error = permit.attach(vec![0; 5]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(budget.normal.available_permits(), 4);
    }

    #[tokio::test]
    async fn cancelled_acquire_does_not_consume_capacity() {
        let budget = PacketBodyBudget::new(4, 1).unwrap();
        let error = budget.acquire_normal(ready(())).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(budget.normal.available_permits(), 4);
    }
}
