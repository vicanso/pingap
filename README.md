# pingap

## Http peer 复用

```rust
fn peer_hash(&self) -> u64 {
    let mut hasher = AHasher::default();
    self.hash(&mut hasher);
    hasher.finish()
}
```
