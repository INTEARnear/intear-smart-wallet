use std::ops::{Deref, DerefMut};

use near_sdk::{
    IntoStorageKey,
    borsh::{BorshDeserialize, BorshSerialize},
};

/// A wrapper around a storage cell that automatically serializes and deserializes the data,
/// but is not stored in the contract state itself, so that the contract state can be
/// empty, storage keys don't need to be stored (since they're hardcoded in most cases anyway),
/// and accessing a default value doesn't store it until it's modified.
pub struct StorageCell<T: BorshSerialize + BorshDeserialize + Default> {
    data: T,
    key: Box<[u8]>,
    was_modified: bool,
}

impl<T: BorshSerialize + BorshDeserialize + Default> StorageCell<T> {
    pub fn load(key: impl IntoStorageKey) -> Self {
        let key = key.into_storage_key();
        if let Some(data) = near_sdk::env::storage_read(&key) {
            Self {
                data: BorshDeserialize::deserialize(&mut data.as_slice())
                    .expect("Failed to deserialize recovery methods"),
                key: key.into_boxed_slice(),
                was_modified: false,
            }
        } else {
            Self {
                data: T::default(),
                key: key.into_boxed_slice(),
                was_modified: false,
            }
        }
    }

    pub fn flush(&mut self) {
        if self.was_modified {
            let mut data = Vec::new();
            BorshSerialize::serialize(&self.data, &mut data).expect("Failed to serialize data");
            near_sdk::env::storage_write(&self.key, &data);
        }
    }
}

impl<T: BorshSerialize + BorshDeserialize + Default> Drop for StorageCell<T> {
    fn drop(&mut self) {
        self.flush();
    }
}

impl<T: BorshSerialize + BorshDeserialize + Default> AsRef<T> for StorageCell<T> {
    fn as_ref(&self) -> &T {
        &self.data
    }
}

impl<T: BorshSerialize + BorshDeserialize + Default> AsMut<T> for StorageCell<T> {
    fn as_mut(&mut self) -> &mut T {
        self.was_modified = true;
        &mut self.data
    }
}

impl<T: BorshSerialize + BorshDeserialize + Default> Deref for StorageCell<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: BorshSerialize + BorshDeserialize + Default> DerefMut for StorageCell<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.was_modified = true;
        &mut self.data
    }
}
