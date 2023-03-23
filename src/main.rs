use std::{fs, mem};
use std::os::fd::AsRawFd;
use nix::ioctl_write_int;
use std::{thread, time};
use cty;

//const IFF_TUN: cty::c_short = 0x0001;
const IFF_TAP: cty::c_short = 0x0002;
const IFF_NO_PI: cty::c_short = 0x1000;

// libc::ifreq doesn't match linux representation of a linux/if.h:ifreq structure, which looks very strange...
#[ repr(C) ]
pub struct ifreq {
    pub ifr_name: [cty::c_char; 16],
    pub ifr_flags: cty::c_short
}

fn main() {
    let tun_file = fs::OpenOptions::new()
        .read( true )
        .write( true )
        .create( false )
        .open( "/dev/net/tun" ).expect( "Failed to open a /dev/net/tun file" );

    // TODO: implement a Display trait 
    let mut ifreq = ifreq {
        ifr_name: [ 0; 16 ],
        ifr_flags: IFF_TAP | IFF_NO_PI,
    };

    // TODO: is there more sane way to initialize an array in rust?
    ifreq.ifr_name[ 0 ] = 't' as cty::c_char;
    ifreq.ifr_name[ 1 ] = 'a' as cty::c_char;
    ifreq.ifr_name[ 2 ] = 'p' as cty::c_char;
    ifreq.ifr_name[ 3 ] = '0' as cty::c_char; 
    ifreq.ifr_name[ 4 ] =  0  as cty::c_char;

    const TUN_IOC_MAGIC: u8 = 'T' as u8;
    const TUN_IOC_SET_IFF: u8 = 202;
    ioctl_write_int!( hci_dev_up, TUN_IOC_MAGIC, TUN_IOC_SET_IFF );

    unsafe { 
        println!( "Trying to setup tap interface, ifr_flags: {}...", ifreq.ifr_flags );

        hci_dev_up( tun_file.as_raw_fd(), mem::transmute::<&ifreq, u64>( &ifreq ) ).expect( "failed to setup tap interface" );
        println!( "Tap interface has been setup" );
    };

    println!( "Waiting..." );
    thread::sleep( time::Duration::from_secs( 30 ) );
}
