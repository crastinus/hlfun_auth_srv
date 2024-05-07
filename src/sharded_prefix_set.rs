use std::sync::RwLock;

use iprange::IpRange;

const SHARD_AMOUNT_SHIFT: usize = 7;

// in addition to sharding this trie must have lower depth
pub struct ShardedPrefixSet {
    prefix_set: [RwLock<IpRange<ipnet::Ipv4Net>>; 1 << SHARD_AMOUNT_SHIFT],
}

impl ShardedPrefixSet {
    pub fn new() -> ShardedPrefixSet {
        assert!(SHARD_AMOUNT_SHIFT <= 8);
        ShardedPrefixSet {
            prefix_set: std::array::from_fn(|_| RwLock::new(IpRange::new())),
        }
    }

    #[inline(always)]
    fn shard_id(&self, subnet: ipnet::Ipv4Net) -> usize {
        let octet = subnet.addr().octets()[0];
        let shard = octet >> (8 - SHARD_AMOUNT_SHIFT);
        shard as usize
    }

    pub fn contains(&self, subnet: ipnet::Ipv4Net) -> bool {
        self.prefix_set[self.shard_id(subnet)]
            .read()
            .unwrap()
            .contains(&subnet)
    }

    pub fn insert(&self, subnet: ipnet::Ipv4Net) {
        self.prefix_set[self.shard_id(subnet)]
            .write()
            .unwrap()
            .add(subnet);
    }

    pub fn remove(&self, subnet: ipnet::Ipv4Net) {
        self.prefix_set[self.shard_id(subnet)]
            .write()
            .unwrap()
            .remove(subnet);
    }
}
