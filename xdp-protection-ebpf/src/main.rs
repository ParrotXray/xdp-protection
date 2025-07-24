#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_smp_processor_id, bpf_map_lookup_percpu_elem},
    macros::{map, xdp},
    maps::{PerCpuArray, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core;
use xdp_protection_common::{
    ExecutionError,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[derive(Clone, Copy)]
enum ActionType {
    Allow,
    Warn,
    PartialDrop,
    Block,
}

#[map]
static COUNTER: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

#[map]
static IP_COUNTER: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

const CPU_CORES: u32 = 4;
const THRESHOLD_WARN: u32 = 20;    
const THRESHOLD_PARTIAL: u32 = 40; 
const THRESHOLD_BLOCK: u32 = 100; 

const IP_WARN_LIMIT: u32 = 10;    
const IP_PARTIAL_LIMIT: u32 = 20; 
const IP_BLOCK_LIMIT: u32 = 30; 

#[xdp]
pub fn xdp_protection(ctx: XdpContext) -> u32 {
    match try_xdp_protection(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn get_total_cpu_counter() -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..CPU_CORES {
        let c = unsafe {
            bpf_map_lookup_percpu_elem(
                &COUNTER as *const _ as *mut core::ffi::c_void,
                &0u32 as *const _ as *const core::ffi::c_void,
                cpu,
            )
        };
        if !c.is_null() {
            unsafe {
                let counter = &*(c as *const u32);
                sum += *counter;
            }
        }
    }
    sum
}

fn is_protected_service(src_port: u16, dst_port: u16) -> bool {
    matches!(src_port, 53 | 22 | 5353 | 67 | 68 | 123) || 
    matches!(dst_port, 53 | 22 | 5353 | 67 | 68 | 123)
}

fn try_xdp_protection(ctx: XdpContext) -> Result<u32, ExecutionError> {
    let eth_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, 0)?;
    
    // Check the EtherType of the packet. If it's not an IPv4 packet, pass it along without further processing
    // We have to use unsafe here because we're dereferencing a raw pointer
    match unsafe { (*eth_hdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ip_hdr: *mut Ipv4Hdr = get_mut_ptr_at(&ctx, EthHdr::LEN)?;
    
    match unsafe { (*ip_hdr).proto } {
        IpProto::Udp => {},
        _ => return Ok(xdp_action::XDP_PASS),
    }
    
    // TODO: Only IPv4 + UDP packets will only be executed here

    // Using the IPv4 header length, obtain a pointer to the UDP header
    let udp_hdr: *const UdpHdr = get_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let port = u16::from_be_bytes(unsafe { (*udp_hdr).dest });

    // If the port is 53, pass it along without further processing.
    if port == 53 || port == 22 {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe {
        let src_ip = u32::from_be_bytes((*ip_hdr).src_addr);
        let dst_ip = u32::from_be_bytes((*ip_hdr).dst_addr);
        let src_port = u16::from_be_bytes((*udp_hdr).source);
        let dst_port = u16::from_be_bytes((*udp_hdr).dest);
        let cpu = bpf_get_smp_processor_id();
        let total = get_total_cpu_counter();

        if is_protected_service(src_port, dst_port) {
            info!(&ctx, "SERVICE: {:i}:{} -> {:i}:{}", 
                src_ip, src_port, dst_ip, dst_port);
            return Ok(xdp_action::XDP_PASS);
        }

        let total_packets = {
            let counter = COUNTER
                .get_ptr_mut(0)
                .ok_or(ExecutionError::FailedToGetCounter)?;

            *counter += 1;
            *counter
        };

        let ip_count = {
            let current_count = IP_COUNTER.get(&src_ip).copied().unwrap_or(0);
            let new_count = current_count + 1;
            let _ = IP_COUNTER.insert(&src_ip, &new_count, 0);
            new_count
        };

        let action = determine_action(total_packets, ip_count, src_ip, src_port, dst_port);

        match action {
            ActionType::Allow => {
                info!(&ctx, "ALLOW: {:i}:{} -> :{} (global:{}, ip:{})", 
                    src_ip, src_port, dst_port, total_packets, ip_count);
                Ok(xdp_action::XDP_PASS)
            }
            ActionType::Warn => {
                info!(&ctx, "WARN: {:i}:{} -> :{} (global:{}, ip:{})", 
                    src_ip, src_port, dst_port, total_packets, ip_count);
                Ok(xdp_action::XDP_PASS)
            }
            ActionType::PartialDrop => {
                let should_drop = (total_packets + ip_count) % 3 == 0;
                if should_drop {
                    info!(&ctx, "PARTIAL_DROP: {:i}:{} -> :{} (global:{}, ip:{})", 
                        src_ip, src_port, dst_port, total_packets, ip_count);
                    Ok(xdp_action::XDP_DROP)
                } else {
                    info!(&ctx, "PARTIAL_ALLOW: {:i}:{} -> :{} (global:{}, ip:{})", 
                        src_ip, src_port, dst_port, total_packets, ip_count);
                    Ok(xdp_action::XDP_PASS)
                }
            }
            ActionType::Block => {
                info!(&ctx, "BLOCK: {:i}:{} -> :{} (global:{}, ip:{})", 
                    src_ip, src_port, dst_port, total_packets, ip_count);
                Ok(xdp_action::XDP_DROP)
            }
        }
    }
}

fn determine_action(global_count: u32, ip_count: u32, _src_ip: u32, _src_port: u16, _dst_port: u16) -> ActionType {
    if ip_count >= IP_BLOCK_LIMIT {
        return ActionType::Block;
    }
    
    if ip_count >= IP_PARTIAL_LIMIT {
        return ActionType::PartialDrop;
    }
    
    if global_count <= THRESHOLD_WARN {
        if ip_count >= IP_WARN_LIMIT {
            ActionType::Warn
        } else {
            ActionType::Allow
        }
    } else if global_count <= THRESHOLD_PARTIAL {
        if ip_count >= IP_WARN_LIMIT {
            ActionType::PartialDrop
        } else {
            ActionType::Warn
        }
    } else if global_count <= THRESHOLD_BLOCK {
        ActionType::PartialDrop
    } else {
        ActionType::Block
    }
}

#[inline(always)]
fn get_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ExecutionError> {
    // Get the start and end of the packet data and the size of the type we're trying to access
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    // Ensure the pointer doesn't overflow to prevent undefined behavior and ensure the pointer is not out of bounds
    let new_ptr = start
        .checked_add(offset)
        .ok_or(ExecutionError::PointerOverflow)?;

    if new_ptr
        .checked_add(len)
        .ok_or(ExecutionError::PointerOverflow)?
        > end
    {
        return Err(ExecutionError::PointerOutOfBounds);
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
