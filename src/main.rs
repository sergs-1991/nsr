mod nsr {
    use std::net::Ipv4Addr;
    use mac_address::MacAddress;
    use byte::BytesExt;

    use self::ip::{icmp::{ICMPHeader, ICMPPacket}, IPHeader, IPPacket};

    const DEVICE_NAME: &str = "tap0";
    const IPADDR: Ipv4Addr = Ipv4Addr::new(10, 0, 3, 1);
    const MACADDR: [u8; 6] = [0x44, 0x43, 0x42, 0x41, 0x40, 0x39];

    const ETHERNET_FRAME_SIZE: usize = 1522; //1518 + 4 bytes for optional 802.1Q tag

    mod ethernet {
        use byte::{BE, BytesExt, TryRead, TryWrite, ctx::Bytes};
        use mac_address::MacAddress;
        use std::fmt;

        const ETHERNET_HEADER_SIZE: usize = 14;

        pub struct EthernetHeader {
            pub mac_dest: MacAddress,
            pub mac_src: MacAddress,
            pub ether_type: u16 //TODO: add enum type
        }

        impl EthernetHeader {
            pub fn len(&self) -> usize {
                ETHERNET_HEADER_SIZE
            }
        }

        impl TryRead<'_> for EthernetHeader {
            fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                let offset = &mut 0;
        
                let header = EthernetHeader{
                    mac_dest: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    mac_src: MacAddress::new((bytes.read_with::<&[u8]>(offset, Bytes::Len(6)).unwrap()).try_into().unwrap()),
                    ether_type: bytes.read_with::<u16>(offset, BE).unwrap()
                };

                Ok((header, *offset))
            }
        }

        impl TryWrite for EthernetHeader {
            fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                let offset = &mut 0;

                bytes.write::<&[u8]>(offset, &self.mac_dest.bytes()).unwrap();
                bytes.write::<&[u8]>(offset, &self.mac_src.bytes()).unwrap();
                bytes.write_with(offset, self.ether_type, BE).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for EthernetHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "ethernet header:\n\tmac dest: {}\n\tmac src: {}\n\tether_type: {:#06x}", self.mac_dest, self.mac_src, self.ether_type)
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

                Ok((header, *offset))
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
                bytes.write::<&[u8]>(offset, &self.sha.bytes()).unwrap();
                bytes.write_with::<u32>(offset, self.spa.into(), BE).unwrap();
                bytes.write::<&[u8]>(offset, &self.tha.bytes()).unwrap();
                bytes.write_with::<u32>(offset, self.tpa.into(), BE).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for ARPHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "arp header:\n\thtype: {:#06x}\n\tptype: {:#06x}\n\thlen: {:#04x}\n\t\
                plen: {:#04x}\n\toper: {:#06x}\n\tsha: {}\n\tspa: {}\n\ttha: {}\n\ttpa: {}",
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

    //TODO: generate IP header identifier
    //TODO: manage ttl for nodes implementing a router role 
    //TODO: Explicit Congestion Notification
    //TODO: IP fragmentation
    //TODO: IP options
    //TODO: constrain fields' values which actual size is less then variable size (e.g. ihl is a 4-bit field,
    //      but represented as 8bit variable) 
    mod ip {
        use byte::{BE, BytesExt, TryRead, TryWrite, ctx::Bytes};
        use internet_checksum::checksum;
        use std::{fmt, net::Ipv4Addr};

        pub struct IPPacket {
            header: IPHeader,
            data: Vec<u8>
        }

        impl IPPacket {
            pub fn new(header: IPHeader, data: Vec<u8>) -> Self {
                let mut packet = Self {
                    header,
                    data
                };

                packet.header.total_length = packet.len() as u16;
                packet.header.recalc_checksum();

                packet
            }

            pub fn len(&self) -> usize {
                self.header.ihl as usize * 4 + self.data.len()
            }

            pub fn get_header(&self) -> &IPHeader {
                &self.header
            }

            pub fn get_data(&self) -> &Vec<u8> {
                &self.data
            }
        }

        impl TryRead<'_> for IPPacket {
            fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                let offset = &mut 0;

                let mut packet = IPPacket {
                    header: bytes.read(offset).unwrap(),
                    data: vec![],
                };
                let data_size = (packet.header.total_length - packet.header.ihl as u16 * 4) as usize;
                packet.data = bytes.read_with::<&[u8]>(offset, Bytes::Len(data_size)).unwrap().to_vec();

                Ok((packet, *offset))
            }
        }

        impl TryWrite for IPPacket {
            fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                let offset = &mut 0;

                bytes.write(offset, self.header).unwrap();
                bytes.write::<&[u8]>(offset, self.data.as_ref()).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for IPPacket {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                //write!(f, "{}\n\t{:?}", self.header, self.data)
                write!(f, "{}\n...", self.header)
            }
        }

        #[derive(Clone)]
        pub struct IPHeader {
            version: u8,
            ihl: u8,
            dscp: u8,
            ecn: u8,
            total_length: u16,
            identification: u16,
            flags: u8,
            fragment_offset: u16,
            ttl: u8,
            pub protocol: u8,
            checksum: u16,
            pub source_address: Ipv4Addr,
            pub destination_address: Ipv4Addr
        }

        impl IPHeader {
            pub fn new(source_address: Ipv4Addr, destination_address: Ipv4Addr, protocol: u8) -> Self {
                Self {
                    version: 0x04,
                    ihl: 5,
                    dscp: 0,
                    ecn: 0,
                    total_length: 0,
                    identification: rand::random(),
                    flags: 0x02,
                    fragment_offset: 0,
                    ttl: 255,
                    protocol,
                    checksum: 0,
                    source_address,
                    destination_address
                }
            }

            fn fragmented(&self) -> bool {
                self.flags == 0x01 || self.fragment_offset != 0
            }

            fn recalc_checksum(&mut self) {
                self.checksum = self.calc_checksum();
            }

            fn check_checksum(&self) -> bool {
                self.calc_checksum() == self.checksum
            }

            fn calc_checksum(&self) -> u16 {
                let mut layout = [0u8; 20];
                let mut header = self.clone();

                header.checksum = 0;
                layout.write(&mut 0, header).unwrap();
                checksum(&layout).read_with::<u16>(&mut 0, BE).unwrap()
            }
        }

        impl TryRead<'_> for IPHeader {
            fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                let offset = &mut 0;

                let ver_ihl = bytes.read::<u8>(offset).unwrap();
                let dscp_ecn = bytes.read::<u8>(offset).unwrap();
                let total_lenght = bytes.read_with::<u16>(offset, BE).unwrap();
                let identification = bytes.read_with::<u16>(offset, BE).unwrap();
                let flags_fragment_offset = bytes.read_with::<u16>(offset, BE).unwrap();

                let header = IPHeader{
                    version: ver_ihl >> 4,
                    ihl: ver_ihl & 0x0F,
                    dscp: dscp_ecn >> 2,
                    ecn: dscp_ecn & 0x03,
                    total_length: total_lenght,
                    identification: identification,
                    flags: (flags_fragment_offset >> 13) as u8,
                    fragment_offset: flags_fragment_offset & 0x1FFF,
                    ttl: bytes.read::<u8>(offset).unwrap(),
                    protocol: bytes.read::<u8>(offset).unwrap(),
                    checksum: bytes.read_with::<u16>(offset, BE).unwrap(),
                    source_address: Ipv4Addr::from(bytes.read_with::<u32>(offset, BE).unwrap()),
                    destination_address: Ipv4Addr::from(bytes.read_with::<u32>(offset, BE).unwrap())
                };

                if !header.check_checksum() {
                    println!("IP header checksum incorrect");
                    return Err(byte::Error::BadInput{err: "IP header checksum incorrect"})
                }

                if header.fragmented() {
                    println!("IP fragmentation is not supported");
                    return Err(byte::Error::BadInput{err: "IP fragmentation is not supported"})
                }

                Ok((header, *offset))
            }
        }

        impl TryWrite for IPHeader {
            fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                let offset = &mut 0;

                bytes.write(offset, (self.version << 4) | self.ihl).unwrap();
                bytes.write(offset, (self.dscp << 2) | self.ecn).unwrap();
                bytes.write_with(offset, self.total_length, BE).unwrap();
                bytes.write_with(offset, self.identification, BE).unwrap();
                bytes.write_with(offset, ((self.flags as u16) << 13) | self.fragment_offset, BE).unwrap();
                bytes.write(offset, self.ttl).unwrap();
                bytes.write(offset, self.protocol).unwrap();
                bytes.write_with(offset, self.checksum, BE).unwrap();
                bytes.write_with::<u32>(offset, self.source_address.into(), BE).unwrap();
                bytes.write_with::<u32>(offset, self.destination_address.into(), BE).unwrap();

                Ok(*offset)
            }
        }

        impl fmt::Display for IPHeader {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "ip header:\n\tversion: {}\n\tihl: {}\n\tdscp: {}\n\tecn: {}\n\t\
                total_length: {}\n\tidentification: {}\n\tflags: 0x{:x}\n\tfragment_offset: {}\n\tttl: {}\
                \n\tprotocol: {:#04x}, \n\tchecksum: {:#06x}, \n\tsource_address: {}, \n\tdestination_address: {}",
                self.version, self.ihl, self.dscp, self.ecn, self.total_length, self.identification, self.flags,
                self.fragment_offset, self.ttl, self.protocol, self.checksum, self.source_address,
                self.destination_address)
            }
        }

        pub mod icmp {
            use byte::{BE, BytesExt, TryRead, TryWrite, ctx::Bytes};
            use internet_checksum::checksum;
            use std::fmt;

            const ICMP_HEADER_SIZE: usize = 8;

            pub const ICMP_ECHO_REPLY: u8 = 0;
            pub const ICMP_ECHO_REQUEST: u8 = 8;

            pub struct ICMPPacket {
                header: ICMPHeader,
                data: Vec<u8>
            }

            impl ICMPPacket {
                pub fn new(header: ICMPHeader, data: Vec<u8>) -> Self {
                    let mut packet = Self {
                        header,
                        data
                    };
                    packet.recalc_checksum();

                    packet
                }

                pub fn len(&self) -> usize {
                    ICMP_HEADER_SIZE + self.data.len()
                }

                pub fn get_header(&self) -> &ICMPHeader {
                    &self.header
                }

                pub fn get_data(&self) -> &Vec<u8> {
                    &self.data
                }

                fn recalc_checksum(&mut self) {
                    self.header.checksum = self.calc_checksum();
                }

                fn check_checksum(&self) -> bool {
                    self.calc_checksum() == self.header.checksum
                }

                fn calc_checksum(&self) -> u16 {
                    let mut layout = vec![0u8; ICMP_HEADER_SIZE + self.data.len()];
                    let mut header = self.header.clone();
                    let offset = &mut 0;
                    header.checksum = 0;

                    // we can serialize copy of packet directry but this aproach will require an additional
                    // copying of packet's data
                    layout.as_mut_slice().write(offset, header).unwrap();
                    layout.as_mut_slice().write::<&[u8]>(offset, self.data.as_ref()).unwrap();
                    checksum(&layout).read_with::<u16>(&mut 0, BE).unwrap()
                }
            }

            impl TryRead<'_> for ICMPPacket {
                fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                    let offset = &mut 0;

                    let packet = ICMPPacket{
                        header: bytes.read(offset).unwrap(),
                        data: bytes.read_with::<&[u8]>(offset, Bytes::Len(bytes.len() - *offset)).unwrap().to_vec(),
                    };

                    if !packet.check_checksum() {
                        println!("ICMP header checksum incorrect");
                        return Err(byte::Error::BadInput{err: "ICMP header checksum incorrect"})
                    }

                    Ok((packet, *offset))
                } 
            }

            impl TryWrite for ICMPPacket {
                fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                    let offset = &mut 0;

                    bytes.write(offset, self.header).unwrap();
                    bytes.write::<&[u8]>(offset, self.data.as_ref()).unwrap();

                    Ok(*offset)
                }
            }

            impl fmt::Display for ICMPPacket {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    //write!(f, "{}\n\t{:?}", self.header, self.data)
                    write!(f, "{}\n...", self.header)
                }
            }

            #[derive(Clone)]
            pub struct ICMPHeader {
                pub type_: u8,
                pub code: u8,
                checksum: u16,
                pub rest: [u8; 4]
            }

            impl ICMPHeader {
                pub fn new(type_: u8, code: u8, rest: [u8; 4]) -> Self {
                    ICMPHeader {
                        type_,
                        code,
                        checksum: 0,
                        rest
                    }
                }
            }

            impl TryRead<'_> for ICMPHeader {
                fn try_read(bytes: &[u8], _ctx: ()) -> byte::Result<(Self, usize)> {
                    let offset = &mut 0;
            
                    let header = ICMPHeader{
                        type_: bytes.read(offset).unwrap(),
                        code: bytes.read(offset).unwrap(),
                        checksum: bytes.read_with(offset, BE).unwrap(),
                        rest: (bytes.read_with::<&[u8]>(offset, Bytes::Len(4)).unwrap()).try_into().unwrap()
                    };

                    Ok((header, *offset))
                } 
            }

            impl TryWrite for ICMPHeader {
                fn try_write(self, bytes: &mut [u8], _ctx: ()) -> byte::Result<usize> {
                    let offset = &mut 0;

                    bytes.write(offset, self.type_).unwrap();
                    bytes.write(offset, self.code).unwrap();
                    bytes.write_with(offset, self.checksum, BE).unwrap();   
                    bytes.write::<&[u8]>(offset, &self.rest).unwrap();

                    Ok(*offset)
                }
            }

            impl fmt::Display for ICMPHeader {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "icmp header:\n\ttype: {}\n\tcode: {}\n\tchecksum: {:#06x}\n\trest: {:?}",
                    self.type_, self.code, self.checksum, self.rest)
                }
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
                    println!("Trying to connect to tap interface...");
        
                    ioctl_set_iff(file.as_raw_fd(), mem::transmute::<&Ifreq, u64>(&ifreq)).expect("failed to setup tap interface");
                    println!("Connection to tap interface has been established" );
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
            parse_arp_packet(node, &packet[14..]);
        }
        else if eth_header.ether_type == 0x0800 { //IPv4
            parse_ip_packet(node, &packet[14..]);
        }
        else if eth_header.ether_type == 0x86DD { //IPv6
            println!("IPv6 packet")
        }
        else {
            println!("such packets are not supported!")
        }

        println!("");
    }

    fn parse_ip_packet(node: &mut Node, data: &[u8]) {
        let packet: ip::IPPacket = data.read(&mut 0).unwrap();
        println!("{packet}");

        if packet.get_header().protocol == 0x01 {
            parse_icmp_packet(node, packet.get_data().as_ref());
        }
        if packet.get_header().protocol == 0x06 {
            println!("TCP datagram");
        }
        if packet.get_header().protocol == 0x11 {
            println!("UDP datagram");
        }
    }

    fn parse_icmp_packet(node: &mut Node, data: &[u8]) {
        use ip::icmp;

        let packet: ICMPPacket = data.read(&mut 0).unwrap();
        println!("{packet}");

        match packet.get_header().type_ {
            icmp::ICMP_ECHO_REQUEST => {
                parse_icmp_echo_request(node, &packet);
            }
            _ => {
                println!("unsupported type of icmp packet");
                ()
            }
        }
    }

    fn parse_icmp_echo_request(node: &mut Node, icmp_request: &ICMPPacket) {
        let dest_ip = Ipv4Addr::new(10, 0, 3, 0);
        let dest_mac = match node.arp_cache.get_mac_addr(&dest_ip) {
            Some(mac) => mac,
            None => {
                issue_arp_request(node, dest_ip);
                MacAddress::new([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            }
        };

        let icmp_protocol: u8 = 0x01;

        let icmp_packet = ICMPPacket::new(
            ICMPHeader::new(ip::icmp::ICMP_ECHO_REPLY, 0, icmp_request.get_header().rest.clone()),
            icmp_request.get_data().clone());
        let mut icmp_layout = vec![0u8; icmp_packet.len()];
        icmp_layout.write(&mut 0, icmp_packet).unwrap();

        let ip_packet = IPPacket::new(IPHeader::new(
            node.iff.ip4, dest_ip, icmp_protocol),
            icmp_layout);

        let eth_header = ethernet::EthernetHeader {
            mac_dest: dest_mac,
            mac_src: node.iff.mac,
            ether_type: 0x0800
        };

        let mut reply = vec![0u8; eth_header.len() + ip_packet.len()];
        let offset = &mut 0;

        reply.write(offset, eth_header).unwrap();
        reply.write(offset, ip_packet).unwrap();

        node.iff.device.write_packet(&reply);
    }

    fn parse_arp_packet(node: &mut Node, packet: &[u8]) {
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
