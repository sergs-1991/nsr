use std::{io::Read, io::Write, fs, mem, net::Ipv4Addr};
use std::os::fd::AsRawFd;

use nix::ioctl_write_int;
use cty;
use mac_address::MacAddress;
use byte::{BE, BytesExt, /*ctx::Endian, TryRead, TryWrite*/};

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
/*
struct EthernetFrame<'a> {
    mac_dest: MacAddress,
    mac_src: MacAddress,
    ether_type: u16 //TODO: add enum type
}

impl<'a> TryRead<'a, Endian> for  EthernetFrame<'a> {
    fn try_read(bytes: &'a [u8], endian: Endian) -> Result<(Self, usize)> {
        let mac_dest = MacAddress::new(bytes[0..6].try_into().unwrap());
        let mac_src = MacAddress::new(bytes[6..12].try_into().unwrap());

        let ether_type = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
        let frame = EthernetFrame{
            mac_dest: MacAddress::new(bytes[0..6].try_into().unwrap()),
            mac_src: MacAddress::new(bytes[6..12].try_into().unwrap()),
            ether_type: u16::from_be_bytes(bytes[12..14].try_into().unwrap())
        };

        Ok((frame, 14))
    }
}
*/

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
            println!("size of ethernet frame: {size} bytes");

            self.parse_eth_frame(&ethernet_frame);
        }
    }

    pub fn send_eth_frame(&mut self, frame: &mut [u8]) {
        let mac_dst = MacAddress::new([0x42, 0xd1, 0xbc, 0x59, 0x14, 0x8e]);
        let mac_src = MacAddress::new([0x44, 0x43, 0x42, 0x41, 0x40, 0x39]);
        let ether_type: u16 = 0x0806;

        let offset = &mut 0;
        frame.write_with::<&[u8]>(offset, &mac_dst.bytes(), ()).unwrap();
        frame.write_with::<&[u8]>(offset, &mac_src.bytes(), ()).unwrap();
        frame.write_with::<u16>(offset, ether_type, BE).unwrap();

        match self.interface.write(&frame) {
            Ok(size) => {
                println!("wrote {size} bytes to tap interface")
            }
            Err(err) => {
                println!("failed to write to tap interface, reason: {err}")
            }
        }
    }

    fn parse_eth_frame(&mut self, frame: &[u8]) {
        let mac_dest = MacAddress::new(frame[0..6].try_into().unwrap());
        let mac_src = MacAddress::new(frame[6..12].try_into().unwrap());

        let ether_type = u16::from_be_bytes(frame[12..14].try_into().unwrap());

        println!("mac destination: {mac_dest}");
        println!("mac source: {mac_src}");
        println!("ethertype: 0x{:x}", ether_type);

        if ether_type == 0x0806 {
            self.parse_arp_frame(&frame[14..]);
        }

        println!("");
    }

    fn parse_arp_frame(&mut self, frame: &[u8]) {
        let htype = u16::from_be_bytes(frame[0..2].try_into().unwrap());
        let ptype = u16::from_be_bytes(frame[2..4].try_into().unwrap());
        let hlen = frame[4];
        let plen = frame[5];
        let oper = u16::from_be_bytes(frame[6..8].try_into().unwrap());
        let sha = MacAddress::new(frame[8..14].try_into().unwrap());
        let spa = Ipv4Addr::from(u32::from_be_bytes(frame[14..18].try_into().unwrap()));
        let tha = MacAddress::new(frame[18..24].try_into().unwrap());
        let tpa = Ipv4Addr::from(u32::from_be_bytes(frame[24..28].try_into().unwrap()));

        println!("\nARP request:");
        println!("htype: 0x{:x}", htype);
        println!("ptype: 0x{:x}", ptype);
        println!("hlen: 0x{:x}", hlen);
        println!("plen: 0x{:x}", plen);
        println!("oper: 0x{:x}", oper);
        println!("sha: {sha}");
        println!("spa: {spa}");
        println!("tha: {tha}");
        println!("tpa: {tpa}");

        // issue an arp response 
        let mut arp_response = [0u8; 28 + 14]; // TODO: ugly hack
        let offset = &mut 14;

        let sha_rep = MacAddress::new([0x44, 0x43, 0x42, 0x41, 0x40, 0x39]);
        let spa_rep = Ipv4Addr::new(10, 0, 3, 1);

        arp_response.write_with::<u16>(offset, htype, BE).unwrap();
        arp_response.write_with::<u16>(offset, ptype, BE).unwrap();
        arp_response.write_with::<u8>(offset, hlen, BE).unwrap();
        arp_response.write_with::<u8>(offset, plen, BE).unwrap();
        arp_response.write_with::<u16>(offset, 0x02, BE).unwrap(); // response
        arp_response.write_with::<&[u8]>(offset, &sha_rep.bytes(), ()).unwrap();
        arp_response.write_with::<u32>(offset, spa_rep.into(), BE).unwrap();
        arp_response.write_with::<&[u8]>(offset, &sha.bytes(), ()).unwrap();
        arp_response.write_with::<u32>(offset, spa.into(), BE).unwrap();

        self.send_eth_frame(&mut arp_response);
    }
}


fn main() {
    let mut tap_interface = TapInterface::connect_to_tap_interface(DEVICE_NAME);
    tap_interface.read_eth_frames();
}
