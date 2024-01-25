use std::{fs, mem};
use std::os::fd::AsRawFd;
use nix::ioctl_write_int;
use cty;

use std::{thread, time};

const DEVICE_NAME: &str = "tap0";


const DEVICE_PATH: &str = "/dev/net/tun";

//const IFF_TUN: cty::c_short = 0x0001;
const IFF_TAP: cty::c_short = 0x0002;
const IFF_NO_PI: cty::c_short = 0x1000;


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

fn main() {
    let tun_file = fs::File::options()
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

        ioctl_set_iff( tun_file.as_raw_fd(), mem::transmute::<&Ifreq, u64>( &ifreq ) ).expect( "failed to setup tap interface" );
        println!( "Tap interface has been setup" );
    };

    println!( "Waiting..." );
    thread::sleep( time::Duration::from_secs( 30 ) );
}
