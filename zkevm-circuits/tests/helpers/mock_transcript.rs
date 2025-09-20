use std::{
    io,
    sync::{Arc, Mutex},
};

use ff::PrimeField;
use halo2_proofs::{
    halo2curves::CurveAffine,
    transcript::{
        EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer, TranscriptWrite,
        TranscriptWriterBuffer,
    },
};

/// Typed events captured by [`MockTranscript`] while wrapping an inner transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TEvent {
    AbsorbPoint(Vec<u8>),
    AbsorbScalar(Vec<u8>),
    SqueezeChallenge(Vec<u8>),
}

/// A test helper that wraps an existing transcript and records all absorbed bytes.
///
/// The wrapper delegates to the inner transcript for Fiat-Shamir functionality while
/// storing a copy of every byte sequence absorbed via [`Transcript::common_point`]
/// and [`Transcript::common_scalar`].
#[derive(Clone)]
pub struct MockTranscript<T> {
    inner: T,
    absorbed: Arc<Mutex<Vec<Vec<u8>>>>,
    events: Arc<Mutex<Vec<TEvent>>>,
}

impl<T> MockTranscript<T> {
    /// Creates a new [`MockTranscript`] wrapping the provided transcript instance.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            absorbed: Arc::new(Mutex::new(Vec::new())),
            events: Arc::new(Mutex::new(Vec::new())),
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

    /// Returns the typed event log collected so far.
    pub fn events(&self) -> Vec<TEvent> {
        self.events
            .lock()
            .expect("mock transcript event log poisoned")
            .clone()
    }

    fn record_bytes(&self, bytes: &[u8]) {
        self.absorbed
            .lock()
            .expect("mock transcript log poisoned")
            .push(bytes.to_vec());
    }

    fn record_event(&self, event: TEvent) {
        self.events
            .lock()
            .expect("mock transcript event log poisoned")
            .push(event);
    }
}

impl<T, C, E> Transcript<C, E> for MockTranscript<T>
where
    T: Transcript<C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
{
    fn squeeze_challenge(&mut self) -> E {
        let challenge = self.inner.squeeze_challenge();
        let repr = challenge.get_scalar().to_repr();
        self.record_event(TEvent::SqueezeChallenge(repr.as_ref().to_vec()));
        challenge
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        self.inner.common_point(point)
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.inner.common_scalar(scalar)
    }
}

impl<T, C, E> TranscriptRead<C, E> for MockTranscript<T>
where
    T: TranscriptRead<C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
{
    fn read_point(&mut self) -> io::Result<C> {
        let point = self.inner.read_point()?;
        let encoded = point.to_bytes();
        self.record_bytes(encoded.as_ref());
        self.record_event(TEvent::AbsorbPoint(encoded.as_ref().to_vec()));
        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let scalar = self.inner.read_scalar()?;
        let encoded = scalar.to_repr();
        self.record_bytes(encoded.as_ref());
        self.record_event(TEvent::AbsorbScalar(encoded.as_ref().to_vec()));
        Ok(scalar)
    }
}

impl<T, C, E> TranscriptWrite<C, E> for MockTranscript<T>
where
    T: TranscriptWrite<C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        let encoded = point.to_bytes();
        self.record_bytes(encoded.as_ref());
        self.record_event(TEvent::AbsorbPoint(encoded.as_ref().to_vec()));
        self.inner.write_point(point)
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        let encoded = scalar.to_repr();
        self.record_bytes(encoded.as_ref());
        self.record_event(TEvent::AbsorbScalar(encoded.as_ref().to_vec()));
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

impl<T, R, C, E> TranscriptReadBuffer<R, C, E> for MockTranscript<T>
where
    T: TranscriptReadBuffer<R, C, E>,
    C: CurveAffine,
    E: EncodedChallenge<C>,
    R: io::Read,
{
    fn init(reader: R) -> Self {
        Self::new(<T as TranscriptReadBuffer<R, C, E>>::init(reader))
    }
}
