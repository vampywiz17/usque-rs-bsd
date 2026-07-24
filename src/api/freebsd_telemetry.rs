//! Native FreeBSD host telemetry for Cloudflare device-state reporting.

use std::net::IpAddr;

#[cfg(target_os = "freebsd")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "freebsd")]
use std::marker::PhantomData;
#[cfg(target_os = "freebsd")]
use std::mem::size_of;
#[cfg(target_os = "freebsd")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "freebsd")]
use std::ptr;
#[cfg(target_os = "freebsd")]
use std::time::Instant;

// FreeBSD <net/if_types.h>; libc does not currently export this constant.
#[cfg(target_os = "freebsd")]
const IFT_ETHER: u8 = 0x06;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct HostSnapshot {
    pub interface: Option<InterfaceSnapshot>,
    pub cpu_pct: Option<f32>,
    pub ram_used_pct: Option<f32>,
    pub ram_available_kb: Option<u64>,
    pub disk_usage_pct: Option<f32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceSnapshot {
    pub name: String,
    pub connection_type: String,
    pub network_sent_bps: Option<u64>,
    pub network_rcvd_bps: Option<u64>,
    pub device_ipv4: Option<IpSnapshot>,
    pub device_ipv6: Option<IpSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpSnapshot {
    pub address: String,
    pub netmask: String,
}

#[derive(Default)]
pub struct HostTelemetryCollector {
    #[cfg(target_os = "freebsd")]
    previous_cpu: Option<Vec<u64>>,
    #[cfg(target_os = "freebsd")]
    previous_interface: Option<InterfaceCounters>,
}

#[cfg(target_os = "freebsd")]
#[derive(Clone)]
struct InterfaceCounters {
    name: String,
    received: u64,
    sent: u64,
    sampled_at: Instant,
}

#[cfg(target_os = "freebsd")]
impl HostTelemetryCollector {
    pub fn sample(&mut self, active_ip: Option<IpAddr>) -> HostSnapshot {
        let memory = memory_sample();
        HostSnapshot {
            interface: active_ip.and_then(|ip| self.sample_interface(ip)),
            cpu_pct: self.sample_cpu(),
            ram_used_pct: memory.map(|sample| sample.0),
            ram_available_kb: memory.map(|sample| sample.1),
            disk_usage_pct: disk_usage_sample(),
        }
    }

    fn sample_cpu(&mut self) -> Option<f32> {
        let current = sysctl_unsigned_array("kern.cp_time")?;
        let previous = self.previous_cpu.replace(current.clone())?;
        if current.len() < 5 || current.len() != previous.len() {
            return None;
        }
        let deltas: Vec<u64> = current
            .iter()
            .zip(previous.iter())
            .map(|(now, before)| now.saturating_sub(*before))
            .collect();
        let total = deltas.iter().copied().sum::<u64>();
        if total == 0 {
            return None;
        }
        let idle = deltas[4];
        Some(((total - idle) as f64 / total as f64).clamp(0.0, 1.0) as f32)
    }

    fn sample_interface(&mut self, active_ip: IpAddr) -> Option<InterfaceSnapshot> {
        let mut addresses = unsafe { InterfaceAddresses::load()? };
        let name = addresses.interface_for_ip(active_ip)?;
        let (received, sent, interface_type) = addresses.counters(&name)?;
        let now = Instant::now();
        let rates = self
            .previous_interface
            .as_ref()
            .filter(|previous| previous.name == name)
            .and_then(|previous| {
                let elapsed = now.duration_since(previous.sampled_at).as_secs_f64();
                (elapsed > 0.0).then(|| {
                    (
                        rate(received.saturating_sub(previous.received), elapsed),
                        rate(sent.saturating_sub(previous.sent), elapsed),
                    )
                })
            });
        self.previous_interface = Some(InterfaceCounters {
            name: name.clone(),
            received,
            sent,
            sampled_at: now,
        });
        let (device_ipv4, device_ipv6) = addresses.ip_addresses(&name);

        Some(InterfaceSnapshot {
            name,
            connection_type: connection_type(interface_type).to_string(),
            network_rcvd_bps: rates.map(|value| value.0),
            network_sent_bps: rates.map(|value| value.1),
            device_ipv4,
            device_ipv6,
        })
    }
}

#[cfg(not(target_os = "freebsd"))]
impl HostTelemetryCollector {
    pub fn sample(&mut self, _active_ip: Option<IpAddr>) -> HostSnapshot {
        HostSnapshot::default()
    }
}

#[cfg(all(test, not(target_os = "freebsd")))]
mod portable_tests {
    use super::*;

    #[test]
    fn unsupported_platform_omits_native_metrics() {
        let mut collector = HostTelemetryCollector::default();
        assert_eq!(collector.sample(None), HostSnapshot::default());
    }
}

#[cfg(target_os = "freebsd")]
fn rate(bytes: u64, elapsed_seconds: f64) -> u64 {
    (bytes as f64 / elapsed_seconds)
        .clamp(0.0, u64::MAX as f64)
        .round() as u64
}

#[cfg(target_os = "freebsd")]
fn connection_type(interface_type: u8) -> &'static str {
    if interface_type == IFT_ETHER {
        "ethernet"
    } else {
        "unknown"
    }
}

#[cfg(target_os = "freebsd")]
struct InterfaceAddresses(*mut libc::ifaddrs);

#[cfg(target_os = "freebsd")]
impl InterfaceAddresses {
    unsafe fn load() -> Option<Self> {
        let mut head = ptr::null_mut();
        (libc::getifaddrs(&mut head) == 0).then_some(Self(head))
    }

    fn interface_for_ip(&mut self, target: IpAddr) -> Option<String> {
        self.entries().find_map(|entry| {
            (sockaddr_ip(entry.ifa_addr) == Some(target))
                .then(|| interface_name(entry))
                .flatten()
        })
    }

    fn counters(&mut self, target_name: &str) -> Option<(u64, u64, u8)> {
        self.entries().find_map(|entry| {
            if interface_name(entry).as_deref() != Some(target_name) || entry.ifa_addr.is_null() {
                return None;
            }
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            if family != libc::AF_LINK || entry.ifa_data.is_null() {
                return None;
            }
            let data = unsafe { &*(entry.ifa_data.cast::<libc::if_data>()) };
            Some((data.ifi_ibytes, data.ifi_obytes, data.ifi_type))
        })
    }

    fn ip_addresses(&mut self, target_name: &str) -> (Option<IpSnapshot>, Option<IpSnapshot>) {
        let mut ipv4 = None;
        let mut ipv6 = None;
        for entry in self.entries() {
            if interface_name(entry).as_deref() != Some(target_name) {
                continue;
            }
            match sockaddr_ip(entry.ifa_addr) {
                Some(IpAddr::V4(address)) if ipv4.is_none() => {
                    ipv4 = Some(IpSnapshot {
                        address: address.to_string(),
                        netmask: prefix_length(entry.ifa_netmask).unwrap_or(0).to_string(),
                    });
                }
                Some(IpAddr::V6(address)) if ipv6.is_none() && !address.is_unicast_link_local() => {
                    ipv6 = Some(IpSnapshot {
                        address: address.to_string(),
                        netmask: prefix_length(entry.ifa_netmask).unwrap_or(0).to_string(),
                    });
                }
                _ => {}
            }
        }
        (ipv4, ipv6)
    }

    fn entries(&mut self) -> InterfaceIterator<'_> {
        InterfaceIterator {
            current: self.0,
            owner: PhantomData,
        }
    }
}

#[cfg(target_os = "freebsd")]
impl Drop for InterfaceAddresses {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}

#[cfg(target_os = "freebsd")]
struct InterfaceIterator<'a> {
    current: *mut libc::ifaddrs,
    owner: PhantomData<&'a libc::ifaddrs>,
}

#[cfg(target_os = "freebsd")]
impl<'a> Iterator for InterfaceIterator<'a> {
    type Item = &'a libc::ifaddrs;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.is_null() {
            return None;
        }
        let current = unsafe { &*self.current };
        self.current = current.ifa_next;
        Some(current)
    }
}

#[cfg(target_os = "freebsd")]
fn interface_name(entry: &libc::ifaddrs) -> Option<String> {
    (!entry.ifa_name.is_null()).then(|| unsafe {
        CStr::from_ptr(entry.ifa_name)
            .to_string_lossy()
            .into_owned()
    })
}

#[cfg(target_os = "freebsd")]
fn sockaddr_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match unsafe { (*address).sa_family as i32 } {
        libc::AF_INET => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                address.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let address = unsafe { &*(address.cast::<libc::sockaddr_in6>()) };
            Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

#[cfg(target_os = "freebsd")]
fn prefix_length(netmask: *const libc::sockaddr) -> Option<u32> {
    match sockaddr_ip(netmask)? {
        IpAddr::V4(mask) => Some(u32::from(mask).count_ones()),
        IpAddr::V6(mask) => Some(mask.octets().iter().map(|byte| byte.count_ones()).sum()),
    }
}

#[cfg(target_os = "freebsd")]
fn memory_sample() -> Option<(f32, u64)> {
    let physical = sysctl_unsigned("hw.physmem")?;
    let page_size = sysctl_unsigned("hw.pagesize")?;
    let available_pages = [
        "vm.stats.vm.v_free_count",
        "vm.stats.vm.v_inactive_count",
        "vm.stats.vm.v_cache_count",
        "vm.stats.vm.v_laundry_count",
    ]
    .into_iter()
    .filter_map(sysctl_unsigned)
    .sum::<u64>();
    let available = available_pages.saturating_mul(page_size).min(physical);
    let used_fraction = if physical == 0 {
        return None;
    } else {
        1.0 - available as f64 / physical as f64
    };
    Some((used_fraction.clamp(0.0, 1.0) as f32, available / 1024))
}

#[cfg(target_os = "freebsd")]
fn disk_usage_sample() -> Option<f32> {
    let path = CString::new("/").ok()?;
    let mut stats = unsafe { std::mem::zeroed::<libc::statvfs>() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 || stats.f_blocks == 0 {
        return None;
    }
    let used = stats.f_blocks.saturating_sub(stats.f_bfree);
    Some((used as f64 / stats.f_blocks as f64).clamp(0.0, 1.0) as f32)
}

#[cfg(target_os = "freebsd")]
fn sysctl_unsigned(name: &str) -> Option<u64> {
    let values = sysctl_unsigned_array(name)?;
    values.first().copied()
}

#[cfg(target_os = "freebsd")]
fn sysctl_unsigned_array(name: &str) -> Option<Vec<u64>> {
    let name = CString::new(name).ok()?;
    let mut size = 0usize;
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
    {
        return None;
    }
    let mut bytes = vec![0u8; size];
    if unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return None;
    }
    bytes.truncate(size);
    let width = if bytes.len().is_multiple_of(size_of::<u64>()) {
        size_of::<u64>()
    } else if bytes.len().is_multiple_of(size_of::<u32>()) {
        size_of::<u32>()
    } else {
        return None;
    };
    Some(
        bytes
            .chunks_exact(width)
            .map(|chunk| {
                if width == size_of::<u64>() {
                    u64::from_ne_bytes(chunk.try_into().unwrap())
                } else {
                    u64::from(u32::from_ne_bytes(chunk.try_into().unwrap()))
                }
            })
            .collect(),
    )
}

#[cfg(all(test, target_os = "freebsd"))]
mod tests {
    use super::*;

    #[test]
    fn byte_rate_uses_elapsed_sample_window() {
        assert_eq!(rate(12_000, 2.0), 6_000);
    }

    #[test]
    fn native_host_samples_stay_in_cloudflare_ranges() {
        let mut collector = HostTelemetryCollector::default();
        let first = collector.sample(Some("127.0.0.1".parse().unwrap()));
        let second = collector.sample(Some("127.0.0.1".parse().unwrap()));
        assert!(second
            .cpu_pct
            .is_none_or(|value| (0.0..=1.0).contains(&value)));
        assert!(first
            .ram_used_pct
            .is_none_or(|value| (0.0..=1.0).contains(&value)));
        assert!(first
            .disk_usage_pct
            .is_none_or(|value| (0.0..=1.0).contains(&value)));
    }
}
