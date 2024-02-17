mod nsr {
    use std::net::Ipv4Addr;
    use mac_address::MacAddress;
    use byte::{BytesExt};

    const DEVICE_NAME: &str = "tap0";
    const IPADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
    const MACADDR: [u8; 6] = [0x44, 0x43, 0x42, 0x41, 0x40, 0x39];

    const ETHERNET_FRAME_SIZE: usize = 1522; //1518 + 4 bytes for optional 802.1Q tag

    mod ethernet {
        use byte::{BE, BytesExt, TryRead, TryWrite, ctx::Bytes};
        use mac_address::MacAddress;
        use std::fmt;

        pub struct EthernetHeader {
            pub mac_dest: MacAddress,
            pub mac_src: MacAddress,
            pub ether_type: u16 //TODO: add enum type
        }

        impl TryRead<'_> for EthernetHeader {
            fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                let offset = &mut 0;
        
                let header = EthernetHeader{
                    mac_dest: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    mac_src: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    ether_type: bytes.read_with::<u16>(offset, BE).unwrap()
                };

                Ok((header, 14))
            }
        }

        impl TryWrite for EthernetHeader {
            fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                let offset = &mut 0;

                bytes.write_with::<&[u8]>(offset, &self.mac_dest.bytes(), ()).unwrap();
                bytes.write_with::<&[u8]>(offset, &self.mac_src.bytes(), ()).unwrap();
                bytes.write_with::<u16>(offset, self.ether_type, BE).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for EthernetHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "ethernet header:\n\tmac dest: {}\n\tmac src: {}\n\tether_type: 0x{:x}", self.mac_dest, self.mac_src, self.ether_type)
            }
        }
    }

    mod arp {
        use byte::{BE, BytesExt, TryRead, TryWrite, ctx::Bytes};
        use mac_address::MacAddress;
        use std::{fmt, net::Ipv4Addr, collections::HashMap};

        pub struct ARPHeader {
            pub htype: u16,
            pub ptype: u16,
            pub hlen: u8,
            pub plen: u8,
            pub oper: u16,
            pub sha: MacAddress,
            pub spa: Ipv4Addr,
            pub tha: MacAddress,
            pub tpa: Ipv4Addr
        }

        impl TryRead<'_> for ARPHeader {
            fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                let offset = &mut 0;
        
                let header = ARPHeader{
                    htype: bytes.read_with::<u16>(offset, BE).unwrap(),
                    ptype: bytes.read_with::<u16>(offset, BE).unwrap(),
                    hlen: bytes.read(offset).unwrap(),
                    plen: bytes.read(offset).unwrap(),
                    oper: bytes.read_with::<u16>(offset, BE).unwrap(),
                    sha: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    spa: Ipv4Addr::from(bytes.read_with::<u32>(offset, BE).unwrap()),
                    tha: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    tpa: Ipv4Addr::from(bytes.read_with::<u32>(offset, BE).unwrap()),
                };

                Ok((header, 28))
            } 
        }

        impl TryWrite for ARPHeader {
            fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                let offset = &mut 0;

                bytes.write_with(offset, self.htype, BE).unwrap();
                bytes.write_with(offset, self.ptype, BE).unwrap();
                bytes.write(offset, self.hlen).unwrap();
                bytes.write(offset, self.plen).unwrap();
                bytes.write_with(offset, self.oper, BE).unwrap();     
                bytes.write_with::<&[u8]>(offset, &self.sha.bytes(), ()).unwrap();
                bytes.write_with::<u32>(offset, self.spa.into(), BE).unwrap();
                bytes.write_with::<&[u8]>(offset, &self.tha.bytes(), ()).unwrap();
                bytes.write_with::<u32>(offset, self.tpa.into(), BE).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for ARPHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "arp header:\n\thtype: 0x{:x}\n\tptype: 0x{:x}\n\thlen: 0x{:x}\n\t\
                plen: 0x{:x}\n\toper: 0x{:x}\n\tsha: {}\n\tspa: {}\n\ttha: {}\n\ttpa: {}",
                self.htype, self.ptype, self.hlen, self.plen, self.oper, self.sha, self.spa, self.tha, self.tpa)
            }
        }

        impl Default for ARPHeader {
            fn default() -> Self {
                ARPHeader {
                    htype: 0x01,
                    ptype: 0x0800,
                    hlen: 0x06,
                    plen: 0x04,
                    oper: 0x01,
                    sha: MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    spa: Ipv4Addr::new(0, 0, 0, 0),
                    tha: MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
                    tpa: Ipv4Addr::new(0, 0, 0, 0)
                }
            }
        }

        impl ARPHeader{
            pub fn request() -> Self {
                ARPHeader { ..Default::default() }                    
            }

            #[allow(dead_code)]
            pub fn reply() -> Self {
                ARPHeader { oper: 0x02, ..Default::default() }                    
            }

            pub fn is_probe(&self) -> bool {
                self.spa == Ipv4Addr::new(0, 0, 0, 0)
            }

            pub fn is_request(&self) -> bool {
                self.oper == 1
            }

            pub fn is_announcement(&self) -> bool {
                self.spa == self.tpa
            }
        }

        pub struct ARPCacher {
            cache: HashMap<Ipv4Addr, MacAddress>
        }
    
        impl ARPCacher {
            pub fn new() -> Self {
                ARPCacher {
                    cache: HashMap::new()
                }
            }
    
            pub fn update(&mut self, ip4: Ipv4Addr, mac: MacAddress) {
                self.cache.insert(ip4, mac);
            }
    
            #[allow(dead_code)]
            pub fn get_mac_addr(&self, ip4: &Ipv4Addr) -> Option<MacAddress> {
                self.cache.get(ip4).copied()
            }
        }
    
        impl fmt::Display for ARPCacher {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "arp cache: {:?}", self.cache)
            }
        }
    }

    mod tap {
        use std::{io::Read, io::Write, fs, mem};
        use std::os::fd::AsRawFd;
        use nix::ioctl_write_int;
        use std::fmt;

        const IF_NAME_MAX_LENGTH: usize = 16;

        // libc::ifreq doesn't match linux representation of a linux/if.h:ifreq structure, which looks very strange...
        #[ repr(C) ]
        pub struct Ifreq {
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
        }

        impl fmt::Display for Ifreq {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "interface name: , flags: - NOT IMPLEMENTED")
            }
        }

        pub struct TapInterface {
            file: fs::File
        }
        
        impl TapInterface {
            const DEVICE_PATH: &str = "/dev/net/tun";

            //const IFF_TUN: cty::c_short = 0x0001;
            const IFF_TAP: cty::c_short = 0x0002;
            const IFF_NO_PI: cty::c_short = 0x1000;

            pub fn new(interface_name: &str) -> Self {
                let file = fs::File::options()
                    .read(true)
                    .write(true)
                    .create(false)
                    .open(TapInterface::DEVICE_PATH).expect("Failed to open a {DEVICE_PATH} file");
        
                let ifreq = Ifreq::new(interface_name, TapInterface::IFF_TAP | TapInterface::IFF_NO_PI);
        
                const TUN_IOC_MAGIC: u8 = 'T' as u8;
                const TUN_IOC_SET_IFF: u8 = 202;
                ioctl_write_int!(ioctl_set_iff, TUN_IOC_MAGIC, TUN_IOC_SET_IFF);
        
                unsafe {
                    println!("Trying to setup tap interface...");
        
                    ioctl_set_iff(file.as_raw_fd(), mem::transmute::<&Ifreq, u64>(&ifreq)).expect("failed to setup tap interface");
                    println!("Tap interface has been setup" );
                };
        
                TapInterface{file: file}
            }
        
            pub fn read_packet(&mut self) -> [u8; super::ETHERNET_FRAME_SIZE] {
                let mut packet = [0u8; super::ETHERNET_FRAME_SIZE];
        
                match self.file.read(&mut packet) {
                    Ok(size) => {
                        println!("size of a packet: {size} bytes");
                    }
                    Err(err) => {
                        println!("failed to read from tap interface, reason: {err}");
                    } 
                };

                packet
            }
        
            pub fn write_packet(&mut self, packet: &[u8]) {  
                match self.file.write(packet) {
                    Ok(size) => {
                        println!("wrote {size} bytes to tap interface")
                    }
                    Err(err) => {
                        println!("failed to write to tap interface, reason: {err}")
                    }
                }
            }
        }
    }

    struct Interface {
        ip4: Ipv4Addr,
        mac: MacAddress,
        device: tap::TapInterface
    }

    pub struct Node {
        iff: Interface,
        arp_cache: arp::ARPCacher
    }

    impl Node {
        pub fn new() -> Node {
            Node {
                iff: Interface {
                    ip4: IPADDR,
                    mac: MacAddress::new(MACADDR),
                    device: tap::TapInterface::new(DEVICE_NAME),
                },
                arp_cache: arp::ARPCacher::new()
            }
        }

        pub fn handle(&mut self) {
            self.handle_interface();
        }

        fn handle_interface(&mut self) {
            loop {
                let packet = self.iff.device.read_packet();
                parse_eth_packet(self, &packet);

            }
        }
    }

    fn parse_eth_packet(node: &mut Node, packet: &[u8]) {
        let eth_header: ethernet::EthernetHeader = packet.read(&mut 0).unwrap();
        println!("{eth_header}");

        if eth_header.ether_type == 0x0806 {
            parse_arp_frame(node, &packet[14..]);
        }
        else if eth_header.ether_type == 0x0800 { //IPv4
            println!("IPv4 packet")
        }
        else if eth_header.ether_type == 0x86DD { //IPv6
            println!("IPv6 packet")
        }
        else {
            println!("such packets are not supported!")
        }

        println!("");
    }

    fn parse_arp_frame(node: &mut Node, packet: &[u8]) {
        let mut arp_header: arp::ARPHeader = packet.read(&mut 0).unwrap();
        println!("{arp_header}");

        if !arp_header.is_probe() {
            node.arp_cache.update(arp_header.spa, arp_header.sha);
            println!("{}", node.arp_cache);
        }

        if !arp_header.is_announcement() && arp_header.is_request() && arp_header.tpa == node.iff.ip4 {
            // issue an arp response 
            let eth_header = ethernet::EthernetHeader {
                mac_dest: arp_header.sha,
                mac_src: node.iff.mac,
                ether_type: 0x0806
            };

            arp_header.tha = arp_header.sha;
            arp_header.tpa = arp_header.spa;
            arp_header.sha = node.iff.mac;
            arp_header.spa = node.iff.ip4;
            arp_header.oper = 0x02;

            let mut arp_response = [0u8; 14 + 28];
            let offset = &mut 0;
            
            arp_response.write(offset, eth_header).unwrap();
            arp_response.write(offset, arp_header).unwrap();

            node.iff.device.write_packet(&arp_response);
        }
    }

    #[allow(dead_code)]
    pub fn issue_arp_request(node: &mut Node, ip: Ipv4Addr) {
        let mut arp_header = arp::ARPHeader::request();

        let eth_header = ethernet::EthernetHeader {
            mac_dest: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            mac_src: node.iff.mac,
            ether_type: 0x0806
        };

        arp_header.sha = node.iff.mac;
        arp_header.spa = node.iff.ip4;
        arp_header.tha = MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        arp_header.tpa = ip;

        let mut arp_request = [0u8; 14 + 28];
        let offset = &mut 0;
        
        arp_request.write(offset, eth_header).unwrap();
        arp_request.write(offset, arp_header).unwrap();

        node.iff.device.write_packet(&arp_request);
    }

    #[allow(dead_code)]
    pub fn issue_arp_probe(node: &mut Node, ip: Ipv4Addr) {
        let mut arp_header = arp::ARPHeader::request();

        let eth_header = ethernet::EthernetHeader {
            mac_dest: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            mac_src: node.iff.mac,
            ether_type: 0x0806
        };

        arp_header.sha = node.iff.mac;
        arp_header.spa = Ipv4Addr::new(0, 0, 0, 0);
        arp_header.tha = MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        arp_header.tpa = ip;

        let mut arp_probe = [0u8; 14 + 28];
        let offset = &mut 0;
        
        arp_probe.write(offset, eth_header).unwrap();
        arp_probe.write(offset, arp_header).unwrap();

        node.iff.device.write_packet(&arp_probe);
    }

    #[allow(dead_code)]
    pub fn issue_arp_announcement(node: &mut Node) {
        let mut arp_header = arp::ARPHeader::request();

        let eth_header = ethernet::EthernetHeader {
            mac_dest: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            mac_src: node.iff.mac,
            ether_type: 0x0806
        };

        arp_header.sha = node.iff.mac;
        arp_header.spa = node.iff.ip4;
        arp_header.tha = MacAddress::new([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        arp_header.tpa = arp_header.spa;

        let mut arp_announcement = [0u8; 14 + 28];
        let offset = &mut 0;
        
        arp_announcement.write(offset, eth_header).unwrap();
        arp_announcement.write(offset, arp_header).unwrap();

        node.iff.device.write_packet(&arp_announcement);
    }

    #[allow(dead_code)]
    pub fn issue_arp_announcement_reply(node: &mut Node) {
        let mut arp_header = arp::ARPHeader::reply();

        let eth_header = ethernet::EthernetHeader {
            mac_dest: MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            mac_src: node.iff.mac,
            ether_type: 0x0806
        };

        arp_header.sha = node.iff.mac;
        arp_header.spa = node.iff.ip4;
        arp_header.tha = MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        arp_header.tpa = arp_header.spa;

        let mut arp_announcement = [0u8; 14 + 28];
        let offset = &mut 0;

        arp_announcement.write(offset, eth_header).unwrap();
        arp_announcement.write(offset, arp_header).unwrap();

        node.iff.device.write_packet(&arp_announcement);
    }

    #[allow(dead_code)]
    pub fn make_active_arp(node: &mut Node) {
        issue_arp_request(node, Ipv4Addr::new(192, 168, 0, 105));
        issue_arp_probe(node, Ipv4Addr::new(192, 168, 0, 105));
        issue_arp_announcement(node);
        issue_arp_announcement_reply(node);
    }
}

fn main() {
    let mut node = nsr::Node::new();
    //nsr::make_active_arp(&mut node);
    node.handle();
}
