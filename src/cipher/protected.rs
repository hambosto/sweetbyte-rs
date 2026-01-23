use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Result;
use std::ops::Deref;
use zeroize::Zeroize;

#[derive(Clone)]
pub struct Protected<T>
where
    T: Zeroize,
{
    data: T,
}

impl<T> Deref for Protected<T>
where
    T: Zeroize,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> Protected<T>
where
    T: Zeroize,
{
    pub fn new(value: T) -> Self {
        Protected { data: value }
    }

    pub fn expose(&self) -> &T {
        &self.data
    }
}

impl<T> Drop for Protected<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl<T> Debug for Protected<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.write_str("[REDACTED]")
    }
}
