#![no_std]

// 錯誤類型定義
#[derive(Clone, Copy, Debug)]
pub enum ExecutionError {
    PointerOverflow,
    PointerOutOfBounds,
    FailedToGetCounter,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct IpRecord {
    pub count: u32,
    pub last_seen: u64,
}

impl IpRecord {
    pub fn new(count: u32, last_seen: u64) -> Self {
        Self { count, last_seen }
    }
    
    pub fn increment(&mut self, current_time: u64) {
        self.count += 1;
        self.last_seen = current_time;
    }
    
    pub fn reset(&mut self, current_time: u64) {
        self.count = 1;
        self.last_seen = current_time;
    }
}