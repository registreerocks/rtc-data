use std::fmt::{Debug, Display};

// TODO: Pull this into the rtc_types library?

pub trait MergeError<T, Err1, Err2>
where
    Err1: Display + Debug,
    Err2: Display + Debug,
{
    fn merge_err(self) -> Result<T, MergedError<Err1, Err2>>;
}

impl<T, Err1, Err2> MergeError<T, Err1, Err2> for Result<Result<T, Err1>, Err2>
where
    Err1: Display + Debug,
    Err2: Display + Debug,
{
    fn merge_err(self) -> Result<T, MergedError<Err1, Err2>> {
        match self {
            Ok(inner_result) => inner_result.map_err(|inner_err| MergedError::Error1(inner_err)),
            Err(err) => Err(MergedError::Error2(err)),
        }
    }
}

#[derive(Clone)]
pub enum MergedError<Err1, Err2>
where
    Err1: Display + Debug,
    Err2: Display + Debug,
{
    Error1(Err1),
    Error2(Err2),
}

impl<Err1, Err2> Display for MergedError<Err1, Err2>
where
    Err1: Display + Debug,
    Err2: Display + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergedError::Error1(err) => (err as &dyn Display).fmt(f),
            MergedError::Error2(err) => (err as &dyn Display).fmt(f),
        }
    }
}

impl<Err1, Err2> Debug for MergedError<Err1, Err2>
where
    Err1: Display + Debug,
    Err2: Display + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MergedError::Error1(err) => (err as &dyn Debug).fmt(f),
            MergedError::Error2(err) => (err as &dyn Debug).fmt(f),
        }
    }
}
