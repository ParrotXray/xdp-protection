#![no_std]

// 錯誤類型定義
#[derive(Clone, Copy, Debug)]
pub enum ExecutionError {
    PointerOverflow,
    PointerOutOfBounds,
    FailedToGetCounter,
}
