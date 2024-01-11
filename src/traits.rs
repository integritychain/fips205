

pub trait PK {
    type Seed;
    fn seed(&self) -> Self::Seed;
}