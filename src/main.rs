use std::{fs, mem};
use std::os::fd::AsRawFd;
use nix::ioctl_write_int;
use std::io::Read;
use cty;
use mac_address::MacAddress;


const DEVICE_NAME: &str = "tap0";


const DEVICE_PATH: &str = "/dev/net/tun";

//const IFF_TUN: cty::c_short = 0x0001;
const IFF_TAP: cty::c_short = 0x0002;
const IFF_NO_PI: cty::c_short = 0x1000;

const IF_NAME_MAX_LENGTH: usize = 16;
const ETHERNET_FRAME_SIZE: usize = 1522; //1518 + 4 bytes for optional 802.1Q tag


// libc::ifreq doesn't match linux representation of a linux/if.h:ifreq structure, which looks very strange...
#[ repr(C) ]
struct Ifreq {
    ifr_name: [cty::c_char; IF_NAME_MAX_LENGTH],
    ifr_flags: cty::c_short
}

impl Ifreq {
    pub fn new(name: &str, flags: cty::c_short) -> Self {
        let mut ifreq = Self {
            ifr_name: [ 0; 16 ],
            ifr_flags: flags,
        };

        ifreq.setup_name(name);
        ifreq
    }

    fn setup_name(&mut self, name: &str) {
        if name.len() > IF_NAME_MAX_LENGTH - 1 {
            panic!("invalid name of interface");
        }

        for (idx, c) in name.chars().enumerate() {
            self.ifr_name[idx] = c as cty::c_char;
        }
    }

    // TODO: implement a Display trait 
}

struct TapInterface {
    interface: fs::File
}

impl TapInterface {
    pub fn connect_to_tap_interface(interface_name: &str) -> Self {
        let tap_interface = fs::File::options()
            .read(true)
            .write(true)
            .create(false)
            .open(DEVICE_PATH).expect("Failed to open a {DEVICE_PATH} file");

        let ifreq = Ifreq::new(interface_name, IFF_TAP | IFF_NO_PI);

        const TUN_IOC_MAGIC: u8 = 'T' as u8;
        const TUN_IOC_SET_IFF: u8 = 202;
        ioctl_write_int!(ioctl_set_iff, TUN_IOC_MAGIC, TUN_IOC_SET_IFF);

        unsafe {
            println!("Trying to setup tap interface, ifr_flags: {}...", ifreq.ifr_flags);

            ioctl_set_iff(tap_interface.as_raw_fd(), mem::transmute::<&Ifreq, u64>(&ifreq)).expect("failed to setup tap interface");
            println!("Tap interface has been setup" );
        };

        TapInterface{interface: tap_interface}
    }

    pub fn read_eth_frames(&mut self) {
        let mut ethernet_frame = [0u8; ETHERNET_FRAME_SIZE];

        loop {
            let size = match self.interface.read(&mut ethernet_frame) {
                Ok(size) => size,
                Err(err) => {
                    println!("failed to read from tap interface, reason: {err}");
                    continue;
                }
            };
            println!("size of ethernet frame: {size}");

            Self::parse_eth_frame(&ethernet_frame);
        }
    }

    fn parse_eth_frame(frame: &[u8]) {
        let mac_dest = MacAddress::new(frame[0..6].try_into().unwrap());
        let mac_src = MacAddress::new(frame[6..12].try_into().unwrap());

        let ether_type = u16::from_be_bytes(frame[12..14].try_into().unwrap());

        println!("mac destination: {mac_dest}");
        println!("mac source: {mac_src}");
        println!("ethertype: 0x{:x}", ether_type);
        println!("");
    }
}


fn main() {
    let mut tap_interface = TapInterface::connect_to_tap_interface(DEVICE_NAME);
    tap_interface.read_eth_frames();
}
