use std::{
    io,
    sync::{Arc, Mutex},
};

use ff::PrimeField;
use halo2_proofs::{
    halo2curves::CurveAffine,
    transcript::{EncodedChallenge, Transcript, TranscriptWrite, TranscriptWriterBuffer},
};

/// A test helper that wraps an existing transcript and records all absorbed bytes.
///
/// The wrapper delegates to the inner transcript for Fiat-Shamir functionality while
/// storing a copy of every byte sequence absorbed via [`Transcript::common_point`]
/// and [`Transcript::common_scalar`].
#[derive(Clone)]
pub struct MockTranscript<T> {
    inner: T,
    absorbed: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl<T> MockTranscript<T> {
    /// Creates a new [`MockTranscript`] wrapping the provided transcript instance.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            absorbed: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Returns a snapshot of all byte sequences absorbed into the transcript.
    pub fn absorbed_messages(&self) -> Vec<Vec<u8>> {
        self.absorbed
            .lock()
            .expect("mock transcript log poisoned")
            .clone()
    }

    /// Consumes the wrapper and returns the inner transcript value.
    pub fn into_inner(self) -> T {
        self.inner
    }

    fn record_bytes(&self, bytes: &[u8]) {
        self.absorbed
            .lock()
            .expect("mock transcript log poisoned")
            .push(bytes.to_vec());
    }
}

impl<T, C, E> Transcript<C, E> for MockTranscript<T>
where
    T: Transcript<C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
{
    fn squeeze_challenge(&mut self) -> E {
        self.inner.squeeze_challenge()
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        let encoded = point.to_bytes();
        self.record_bytes(encoded.as_ref());
        self.inner.common_point(point)
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        let encoded = scalar.to_repr();
        self.record_bytes(encoded.as_ref());
        self.inner.common_scalar(scalar)
    }
}

impl<T, C, E> TranscriptWrite<C, E> for MockTranscript<T>
where
    T: TranscriptWrite<C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        self.inner.write_point(point)
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.inner.write_scalar(scalar)
    }
}

impl<T, W, C, E> TranscriptWriterBuffer<W, C, E> for MockTranscript<T>
where
    T: TranscriptWriterBuffer<W, C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
    W: io::Write,
{
    fn init(writer: W) -> Self {
        Self::new(<T as TranscriptWriterBuffer<W, C, E>>::init(writer))
    }

    fn finalize(self) -> W {
        self.inner.finalize()
    }
}
