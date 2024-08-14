mod parse_input;

use std::io::{BufReader, Read, Result};
use std::fs::File;
use std::convert::TryInto;
use std::collections::VecDeque;

macro_rules! from_le_bytes_typed {
    ($buf: expr, $typ: ty) => {
        <$typ>::from_le_bytes($buf.try_into().unwrap())
    };
}

macro_rules! to_str {
    ($slice: expr) => {
        std::str::from_utf8($slice)
    };
}

#[derive(Default, Debug, Copy, Clone)]
struct QuotePackets {
    pkt_time_hours: u8,
    pkt_time_minutes: u8,
    pkt_time_seconds: u8,
    pkt_time_microseconds: u32,
    pkt_time_microseconds_total: u64,
    accept_time_hours: u8,
    accept_time_minutes: u8,
    accept_time_seconds: u8,
    accept_time_microseconds: u8,
    accept_time_microseconds_total: u64, 
    issue_code: [u8; 12],
    bid_price: [[u8; 5]; 5],
    bid_qty: [[u8; 7]; 5],
    ask_price: [[u8; 5]; 5],
    ask_qty: [[u8; 7]; 5]
}

impl QuotePackets {
    fn new() -> Self {
        Default::default()
    }
}

fn parse_pcap_header(header_bytes: &[u8]) {
    println!("Parsing pcap header start.");
    
    let magic_number: u32 = from_le_bytes_typed!(header_bytes[0..4], u32);
    println!("Magic number is 0x{:x}, timestamps are in micro-seconds", magic_number);
    
    let snap_len: u32 = from_le_bytes_typed!(header_bytes[16..20], u32);
    println!("Snap length is {}", snap_len);

    let bit_mask = 0b00001111111111111111111111111111 as u32;
    let link_type: u32 = from_le_bytes_typed!(header_bytes[20..24], u32);
    let link_type_bit_masked = bit_mask & link_type;
    println!("Link bit masked is {}, which is Ethernet", link_type_bit_masked);

    println!("Parsing pcap header done.");
    println!();
}

fn parse_packet_header(packet_header_bytes: &[u8], quote_packet: &mut QuotePackets) -> usize {
    // parse packet time
    let time_stamp_seconds_total: u32 = from_le_bytes_typed!(packet_header_bytes[0..4], u32);
    quote_packet.pkt_time_microseconds = from_le_bytes_typed!(packet_header_bytes[4..8], u32);


    // update the quote_packet pkt_time
    quote_packet.pkt_time_hours = ((time_stamp_seconds_total % 86400) / 3600 + 9) as u8;
    quote_packet.pkt_time_minutes = ((time_stamp_seconds_total % 3600) / 60) as u8;
    quote_packet.pkt_time_seconds = (time_stamp_seconds_total % 60) as u8;

    quote_packet.pkt_time_microseconds_total = quote_packet.pkt_time_hours as u64 * 60 * 60 * 1000000 
    + quote_packet.pkt_time_minutes as u64 * 60 * 1000000
    + quote_packet.pkt_time_seconds as u64 * 1000000
    + quote_packet.pkt_time_microseconds as u64;

    // get packet length
    let captured_packet_length: u32 = from_le_bytes_typed!(packet_header_bytes[8..12], u32);
    let original_packet_length: u32 = from_le_bytes_typed!(packet_header_bytes[12..16], u32);
    if captured_packet_length != original_packet_length {
        panic!("Unequal captured_packet_length and original_packet_length");
    }
    captured_packet_length as usize
}

fn parse_packet_contents(packet_contents: &[u8], packet_contents_length: usize, quote_packet: &mut QuotePackets) -> std::result::Result<(), &'static str> {
    let quote_start: usize = 42;

    if quote_start + 5 >  packet_contents_length {
        return Err("No quote_type");
    }

    let quote_type: &str = match to_str!(&packet_contents[quote_start..quote_start+5]) {
        Ok(s) => s,
        Err(_) => return Err("invalid parsing of quote_type"),
    };
    if quote_type != "B6034" {
        return Err("quote_type is not B6034");
    }

    quote_packet.issue_code.copy_from_slice(&packet_contents[quote_start+5..quote_start+17]);

    for i in (0..60).step_by(12) {
        quote_packet.bid_price[i / 12].copy_from_slice(&packet_contents[quote_start+i+29..quote_start+i+29+5]);
        quote_packet.bid_qty[i / 12].copy_from_slice(&packet_contents[quote_start+i+29+5..quote_start+i+29+12]);
    }
    for i in (0..60).step_by(12) {
        quote_packet.ask_price[i / 12].copy_from_slice(&packet_contents[quote_start+i+96..quote_start+i+96+5]);
        quote_packet.ask_qty[i / 12].copy_from_slice(&packet_contents[quote_start+i+96+5..quote_start+i+96+12]);
    }

    let qat: &str = to_str!(&packet_contents[packet_contents_length - 1 - 8..packet_contents_length - 1]).unwrap();
    quote_packet.accept_time_hours = qat[0..2].parse().unwrap();
    quote_packet.accept_time_minutes = qat[2..4].parse().unwrap();
    quote_packet.accept_time_seconds = qat[4..6].parse().unwrap();
    quote_packet.accept_time_microseconds = qat[6..8].parse().unwrap();
    quote_packet.accept_time_microseconds_total = quote_packet.accept_time_hours as u64 * 60 * 60 * 1000000
    + quote_packet.accept_time_minutes as u64 * 60 * 1000000 
    + quote_packet.accept_time_seconds as u64 * 1000000 
    + quote_packet.accept_time_microseconds as u64;

    // let end_of_message: u8 = packet_contents[packet_contents_length-1];
    Ok(())
}

fn print_parsed_quotes(quote_packet: QuotePackets) {
    println!("{:02}:{:02}:{:02}:{:06} {:02}:{:02}:{:02}:{:02} {} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{} {}@{}",
        quote_packet.pkt_time_hours,
        quote_packet.pkt_time_minutes,
        quote_packet.pkt_time_seconds,
        quote_packet.pkt_time_microseconds,
        quote_packet.accept_time_hours,
        quote_packet.accept_time_minutes,
        quote_packet.accept_time_seconds,
        quote_packet.accept_time_microseconds,
        to_str!(&quote_packet.issue_code).unwrap(),
        to_str!(&quote_packet.bid_qty[4]).unwrap(),
        to_str!(&quote_packet.bid_price[4]).unwrap(),
        to_str!(&quote_packet.bid_qty[3]).unwrap(),
        to_str!(&quote_packet.bid_price[3]).unwrap(),
        to_str!(&quote_packet.bid_qty[2]).unwrap(),
        to_str!(&quote_packet.bid_price[2]).unwrap(),
        to_str!(&quote_packet.bid_qty[1]).unwrap(),
        to_str!(&quote_packet.bid_price[1]).unwrap(),
        to_str!(&quote_packet.bid_qty[0]).unwrap(),
        to_str!(&quote_packet.bid_price[0]).unwrap(),
        to_str!(&quote_packet.ask_qty[0]).unwrap(),
        to_str!(&quote_packet.ask_price[0]).unwrap(),
        to_str!(&quote_packet.ask_qty[1]).unwrap(),
        to_str!(&quote_packet.ask_price[1]).unwrap(),
        to_str!(&quote_packet.ask_qty[2]).unwrap(),
        to_str!(&quote_packet.ask_price[2]).unwrap(),
        to_str!(&quote_packet.ask_qty[3]).unwrap(),
        to_str!(&quote_packet.ask_price[3]).unwrap(),
        to_str!(&quote_packet.ask_qty[4]).unwrap(),
        to_str!(&quote_packet.ask_price[4]).unwrap()
    )
}

fn parse_pcap(user_args: parse_input::UserArgs) -> Result<()> {
    let f = File::open(user_args.in_path)?;
    let mut reader = BufReader::new(f);
    let mut header_bytes = vec![0u8; 24];
    reader.read_exact(&mut header_bytes)?;
    parse_pcap_header(&header_bytes);

    let mut packet_header_bytes = vec![0u8; 16];
    // initialize queue for reorder
    let mut queue: VecDeque<QuotePackets> = VecDeque::new();
    loop {
        match reader.read_exact(&mut packet_header_bytes) {
            Ok(()) => {
                let mut quote_packet = QuotePackets::new();
                let packet_contents_length: usize = parse_packet_header(&packet_header_bytes, &mut quote_packet);
                let mut packet_contents = vec![0u8; packet_contents_length];
                reader.read_exact(&mut packet_contents)?;

                let parsed_contents = parse_packet_contents(&packet_contents, packet_contents_length, &mut quote_packet);
                match parsed_contents {
                    Ok(_) => {
                        if user_args.reorder {
                            // insert into correct order of queue
                            if queue.is_empty() {
                                queue.push_front(quote_packet);
                            } else {
                                let mut idx = queue.len();
                                for (i, qp) in queue.iter().enumerate() {
                                    if quote_packet.accept_time_microseconds_total >= qp.accept_time_microseconds_total {
                                        idx = i;
                                        break;
                                    }
                                }
                                queue.insert(idx, quote_packet);
                                
                                // pop front when the oldest packet received time is 3 seconds longer than newly pushed accept time
                                let mut old_packet = queue.back().unwrap();
                                while quote_packet.accept_time_microseconds_total as i64 - old_packet.pkt_time_microseconds_total as i64 > 3000000 {
                                    let popped_packet = queue.pop_back().unwrap();
                                    print_parsed_quotes(popped_packet);
                                    let old_packet_options = queue.back();
                                    match old_packet_options {
                                        Some(x) => old_packet = x,
                                        None => break
                                    };
                                }
                            }
                        } else {
                            print_parsed_quotes(quote_packet);
                        }
                    }
                    Err(_) => ()
                }
            }
            Err(_) => {
                while !queue.is_empty() {
                    // pop and print remaining packets
                    let popped_packet = queue.pop_back().unwrap();
                    print_parsed_quotes(popped_packet);
                }
                break;
            }
        };
    }
    Ok(())
}

// rustc .\parse_quote.rs; .\parse_quote.exe -r mdf-kospi200.20110216-0.pcap
fn main() {
    // get and parse user inputs
    let mut user_args = parse_input::UserArgs::new();
    parse_input::parse_args(&mut user_args);
    let user_args = user_args;

    // parse
    let _ = parse_pcap(user_args).unwrap();
}
