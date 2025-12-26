use std::hash::Hash;
use std::collections::HashMap;
use std::borrow::Borrow;

#[derive(Debug)]
pub struct UnorderedMultiMap<K, V> {
    items: HashMap<K, Vec<V>>,
}

impl <K, V> UnorderedMultiMap<K, V> {
    pub fn new() -> Self {
        Self { items: HashMap::new() }
    }
}

struct ValuesIterator<I> {
    inner: Option<I>
}

impl <I: Iterator> Iterator for ValuesIterator<I> {
    type Item = I::Item;
    fn next(&mut self) -> Option<Self::Item> {
        let iter = self.inner.as_mut()?;
        iter.next()
    }
}

impl <K: Eq + Hash, V> UnorderedMultiMap<K, V> {
    pub fn insert(&mut self, key: K, value: V) {
        match self.items.get_mut(&key) {
            None => {
                self.items.insert(key, vec![value]);
            },
            Some(values) => {
                values.push(value)
            }
        }
    }

    pub fn values_for<Q>(&self, key: &Q) -> impl Iterator<Item=&V>
    where
        K : Borrow<Q>,
        Q: Hash + Eq + ?Sized
    {
        let inner = self.items.get(key).map(|vs| vs.iter());
        ValuesIterator { inner }
    }
}

impl <K, V> UnorderedMultiMap<K, V> {
    pub fn values(&self) -> impl Iterator<Item=&V> {
        let values_it = self.items.iter().flat_map(|(k, v)| v.iter());
        ValuesIterator { inner: Some(values_it) }
    }
}
