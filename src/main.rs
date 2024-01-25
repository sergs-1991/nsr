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

const ETHERNET_FRAME_SIZE: usize = 1522; //1518 + 4 bytes for optional 802.1Q tag


// libc::ifreq doesn't match linux representation of a linux/if.h:ifreq structure, which looks very strange...
#[ repr(C) ]
struct Ifreq {
    ifr_name: [cty::c_char; 16],
    ifr_flags: cty::c_short
}

fn setup_device_name( ifreq: &mut Ifreq, name: &str ) {
    for (idx, c) in name.chars().enumerate() {
        ifreq.ifr_name[idx] = c as cty::c_char;
    }

    ifreq.ifr_name[name.len()] = 0 as cty::c_char;
}

fn parse_eth_frame( frame: &[u8] ) {
    let mac_dest = MacAddress::new( frame[0..6].try_into().unwrap() );
    let mac_src = MacAddress::new( frame[6..12].try_into().unwrap() );

    let ether_type = u16::from_be_bytes( frame[12..14].try_into().unwrap() );

    println!( "mac destination: {mac_dest}" );
    println!( "mac source: {mac_src}" );
    println!( "ethertype: 0x{:x}", ether_type );
}

fn read_eth_frames( tap_device: &mut fs::File ) {
    let mut ethernet_frame = [0u8; ETHERNET_FRAME_SIZE];

    loop {
        let size = tap_device.read( &mut ethernet_frame ).expect( "failed to read from tap interface" );
        println!( "\nsize of ethernet frame: {size}" );

        parse_eth_frame( &ethernet_frame );
    }
}

fn main() {
    let mut tap_device = fs::File::options()
        .read( true )
        .write( true )
        .create( false )
        .open( DEVICE_PATH ).expect( "Failed to open a /dev/net/tun file" );

    // TODO: implement a Display trait 
    let mut ifreq = Ifreq {
        ifr_name: [ 0; 16 ],
        ifr_flags: IFF_TAP | IFF_NO_PI,
    };

    setup_device_name( &mut ifreq, DEVICE_NAME );

    const TUN_IOC_MAGIC: u8 = 'T' as u8;
    const TUN_IOC_SET_IFF: u8 = 202;
    ioctl_write_int!( ioctl_set_iff, TUN_IOC_MAGIC, TUN_IOC_SET_IFF );

    unsafe { 
        println!( "Trying to setup tap interface, ifr_flags: {}...", ifreq.ifr_flags );

        ioctl_set_iff( tap_device.as_raw_fd(), mem::transmute::<&Ifreq, u64>( &ifreq ) ).expect( "failed to setup tap interface" );
        println!( "Tap interface has been setup" );
    };

    read_eth_frames( &mut tap_device );
}
