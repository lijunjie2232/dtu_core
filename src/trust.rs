//! Trust store: devices we authorized, plus the JWT each peer issued for us.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Pinned peer public key (ed25519, base64url).
    pub pubkey: String,
    /// Token the peer issued for us; presented on every connection to that peer.
    pub token: String,
    /// Epoch seconds, 0 = never expires.
    pub expires_at: u64,
    #[serde(default)]
    pub addr: Option<String>,
    /// Human-friendly name, usable anywhere a device id is. Unique in the store
    /// and never equal to any device id.
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub added_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
}

fn path() -> std::path::PathBuf {
    crate::cfg::file("trust.json")
}

impl Store {
    pub fn load() -> Self {
        crate::cfg::read_json(&path()).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        crate::cfg::write_json(&path(), self).map_err(|e| format!("write trust.json: {e}"))
    }

    pub fn get(&self, id: &str) -> Option<&Device> {
        self.devices.get(id).filter(|d| d.expires_at == 0 || d.expires_at > crate::identity::now())
    }

    pub fn get_raw(&self, id: &str) -> Option<&Device> {
        self.devices.get(id)
    }

    pub fn insert(&mut self, id: &str, pubkey: &str, token: &str, expires_at: u64, addr: Option<String>) {
        let added_at = self.devices.get(id).map(|d| d.added_at).unwrap_or_else(crate::identity::now);
        // The alias is ours, not the peer's: re-pairing must not lose it.
        let alias = self.devices.get(id).and_then(|d| d.alias.clone());
        self.devices.insert(
            id.to_string(),
            Device { pubkey: pubkey.to_string(), token: token.to_string(), expires_at, addr, alias, added_at },
        );
    }

    /// Look a peer up by id first, then by alias. Ids win, and aliases are unique.
    pub fn resolve(&self, name: &str) -> Option<(&str, &Device)> {
        if let Some((id, dev)) = self.devices.get_key_value(name) {
            return Some((id.as_str(), dev));
        }
        self.devices
            .iter()
            .find(|(_, d)| d.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(name)))
            .map(|(id, dev)| (id.as_str(), dev))
    }

    /// `None` (or an empty name) clears the alias. Refuses a name that is any
    /// device id or another device's alias, so a name always means one device.
    pub fn set_alias(&mut self, id: &str, alias: Option<&str>) -> Result<(), String> {
        let alias = alias.map(str::trim).filter(|a| !a.is_empty());
        if let Some(a) = alias {
            if self.devices.keys().any(|k| k.eq_ignore_ascii_case(a)) {
                return Err(format!("{a} is a device id, choose another alias"));
            }
            let taken = self
                .devices
                .iter()
                .any(|(other, d)| other.as_str() != id && d.alias.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(a)));
            if taken {
                return Err(format!("alias {a} is already used by another device"));
            }
        }
        let dev = self.devices.get_mut(id).ok_or_else(|| format!("no such device: {id}"))?;
        dev.alias = alias.map(str::to_string);
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        self.devices.remove(id).is_some()
    }
}
