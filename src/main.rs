use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::io::Read;
use std::fs::File;
use std::io::BufReader;
// use std::mem;
use std::io::{self, Write};
// use libc::STDIN_FILENO;
use termios::*;
use std::env;
use std::u16;

#[derive(Debug)]
#[allow(dead_code)]
enum R {
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    PC, /* program counter */
    COND,
    COUNT
}


#[derive(Debug, FromPrimitive)]
enum OP {
    BR = 0,     /* branch */
    ADD,    /* add  */
    LD,     /* load */
    ST,     /* store */
    JSR,    /* jump register */
    AND,    /* bitwise and */
    LDR,    /* load register */
    STR,    /* store register */
    RTI,    /* unused */
    NOT,    /* bitwise not */
    LDI,    /* load indirect */
    STI,    /* store indirect */
    JMP,    /* jump */
    RES,    /* reserved (unused) */
    LEA,    /* load effective address */
    TRAP    /* execute trap */
}

enum FL {
    POS = 1 << 0, /* P */
    ZRO = 1 << 1, /* Z */
    NEG = 1 << 2, /* N */
}

#[derive(FromPrimitive)]
enum TRAP {
    GETC = 0x20,  /* get character from keyboard, not echoed onto the terminal */
    OUT = 0x21,   /* output a character */
    PUTS = 0x22,  /* output a word string */
    IN = 0x23,    /* get character from keyboard, echoed onto the terminal */
    PUTSP = 0x24, /* output a byte string */
    HALT = 0x25   /* halt the program */
}

enum MR{
    KBSR = 0xFE00, /* keyboard status */
    KBDR = 0xFE02  /* keyboard data */
}

fn getchar() -> u8 {
    // assuming 8 bit characters
    let mut buffer: [u8; 1] = [0; 1];
    io::stdout().flush().unwrap(); // flush last message to stdout immediately
    std::io::stdin().read_exact(&mut buffer).expect("Failed at getchar");
    return buffer[0];
}

fn extract(instr: u16, field_ind: u16, field_len: u16) -> usize {
    // Extracts a field from an instruction
    // by bit shifting the instruction to the left
    // and then zeroing out all bits larger than field_len
    return ((instr >> field_ind) & field_len) as usize;
}

fn add(instr: u16, reg: &mut[u16]) {
    // destination register (DR)
    let dr = extract(instr, 9, 0x7);
    // first operand (SR1)
    let sr1 = extract(instr, 6, 0x7);
    // the immediate mode flag
    let imm_flag = extract(instr, 5, 0x1);

    if imm_flag == 1 {
        let imm5 = sign_extend(instr & 0x1F, 5);
        reg[dr] = reg[sr1].wrapping_add(imm5);
    } else {
        let r2 = extract(instr, 0, 0x7);
        reg[dr] = reg[sr1].wrapping_add(reg[r2]);
    }

    update_flags(reg, dr);
}

fn load(mem: &[u16],instr: u16, reg: &mut[u16]) {
    // destination register (DR)
    let dr = extract(instr, 9, 0x7);
    // PCoffset 9
    let pc_offset = sign_extend(instr & 0x1ff, 9);
    let mem_address = reg[R::PC as usize].wrapping_add(pc_offset);
    reg[dr] = mem[mem_address as usize];
    update_flags(reg, dr);
}


fn load_indirect(mem: &mut [u16],instr: u16, reg: &mut[u16]) {
    // destination register (DR)
    let dr = extract(instr, 9, 0x7);
    // PCoffset 9
    let pc_offset = sign_extend(instr & 0x1ff, 9);
    let mem_address = reg[R::PC as usize] + pc_offset;
    let indirect_address = mem_read(mem, mem_address);
    reg[dr] = mem_read(mem, indirect_address);
    update_flags(reg, dr);
}

fn load_register(mem: &[u16], instr: u16, reg: &mut[u16]) {
    let dr = extract(instr, 9, 0x7);
    let br = extract(instr, 6, 0x7);
    let offset = sign_extend(instr & 0x3f, 6);
    let mem_address = reg[br] + offset;
    reg[dr] = mem[mem_address as usize];
    update_flags(reg, dr);
}

fn load_effective_address(instr: u16, reg: &mut[u16]) {
    // destination register (DR)
    let dr = extract(instr, 9, 0x7);
    // PCoffset 9
    let pc_offset = sign_extend(instr & 0x1ff, 9);
    reg[dr] = reg[R::PC as usize] + pc_offset;
    update_flags(reg, dr);
}

fn not(instr: u16, reg: &mut[u16]) {
    let dr = extract(instr, 9, 0x7);
    let sr = extract(instr, 6, 0x7);
    reg[dr] = !reg[sr];
    update_flags(reg, dr);
}

// TODO: thought this was a special case of JMP?
// fn ret(instr: u16, reg: &mut[u16]) {
//     reg[R::PC as usize] = reg[R::R7 as usize];
// }

fn mem_write(mem: &mut[u16], address: u16, val: u16) {
    mem[address as usize] = val;
}

fn store(mem: &mut[u16], instr: u16, reg: &mut[u16]) {
    let sr = extract(instr, 9, 0x7);
    let offset = sign_extend(instr & 0x1FF, 9);
    let mem_address = reg[R::PC as usize].wrapping_add(offset);
    mem_write(mem, mem_address, reg[sr])
}

fn store_indirect(mem: &mut[u16], instr: u16, reg: &mut[u16]) {
    let sr = extract(instr, 9, 0x7);
    let offset = sign_extend(instr & 0x1FF, 9);
    let mem_address = reg[R::PC as usize] + offset;
    let mem_read = mem[mem_address as usize];
    mem_write(mem, mem_read, reg[sr]);
}

fn store_register(mem: &mut[u16], instr: u16, reg: &mut[u16]) {
    let sr = extract(instr, 9, 0x7);
    let br = extract(instr, 6, 0x7);
    let offset = sign_extend(instr & 0x3F, 6);
    // println!("reg[br] is {} and offset is {}", reg[br], offset);
    let mem_address = reg[br].wrapping_add(offset);
    mem_write(mem, mem_address, reg[sr]);
}

fn mem_read(mem: &mut[u16], address: u16) -> u16 {
    if address == MR::KBSR as u16 {
        if getchar() != 0 {
        // if check_key() {
            mem[MR::KBSR as usize] = 1 << 15;
            mem[MR::KBDR as usize] = getchar() as u16;
        } else {
            mem[MR::KBSR as usize] = 0;
        }
    }
    return mem[address as usize];
}

// fn check_key() -> bool {
//     let mut fd = RawFd;
//     fd.insert(STDIN_FILENO);
//
//     let mut timeout = TimeVal::seconds(0);
//     match select::select(1, &mut fd, None, None, &mut timeout) {
//         Err(_) => false,
//         _ => true,
//     }
// }

fn disable_input_buffering(mut termios: &mut Termios, stdin: i32) {
    termios.c_iflag &= IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON;
    termios.c_lflag &= !(ICANON | ECHO); // no echo and canonical mode
    tcsetattr(stdin, TCSANOW, &mut termios).unwrap();
}

fn restore_input_buffering(termios: Termios, stdin: i32) {
    tcsetattr(stdin, TCSANOW, & termios).unwrap();
}

// TODO signal to this function on interrupt
// fn handle_interrupt(termios: Termios, stdin: i32, signal: i32) {
//     restore_input_buffering(termios, stdin);
//     println!();
//     std::process::exit(-2)
// }

fn trap_puts(mem: &mut[u16], reg: &mut[u16]) {
    // slice the memory from address at register 0
    // forward.
    let mem_slice = &mem[reg[R::R0 as usize] as usize..];

    // while the bytes are not zero at the current memory addres...
    for c in mem_slice {
        if *c != 0 {
            let c8 = (c & 0xff) as u8;
            print!("{}", c8 as char);
        } else {
            break;
        }
    }
}

fn trap_getc(reg: &mut[u16]) {
    reg[R::R0 as usize] = getchar() as u16;
}

fn trap_out(reg: &mut[u16]) {
    let c = reg[R::R0 as usize];
    print!("{}", (c as u8) as char);
}

fn trap_in(reg: &mut[u16]) {
    print!("Enter a character: ");
    let c = getchar();
    print!("{}", c as char);
    reg[R::R0 as usize] = (c & 0xff) as u16;
}

fn trap_putsp(mem: &mut[u16], reg: &mut[u16]) {
    let mem_slice = &mem[reg[R::R0 as usize] as usize..];
    // while the bytes are not zero at the current memory addres...
    for c in mem_slice {
        if *c != 0 {
            // print bottom eight bits
            let c_bottom = (c & 0xff) as u8;
            print!("{}", c_bottom as char);
            // print top eights bits
            let c_top = (c >> 8) as u8;
            if c_top != 0 {
                print!("{}", c_top as char);
            }
        } else {
            break;
        }
    }
}

fn two_u8_to_16(two_bytes: &[u8; 2]) -> u16 {
    // swap for endianness
    return swap16(((two_bytes[1] as u16) << 8) | two_bytes[0] as u16);
}

fn read_image_file(mem: &mut[u16], file: File) {
    // read the first 16 bits which is where in memory
    // we want the file to be loaded.
    let mut buffer: [u8; 2] = [0; 2];
    let mut buf_reader = BufReader::new(file);
    // handle read_exact better
    buf_reader.read_exact(&mut buffer).unwrap();
    let mut mem_address: u16 = two_u8_to_16(&buffer);

    while mem_address < u16::max_value() {
        // handle read_exact better here as well
        let eof = buf_reader.read_exact(&mut buffer).is_err();
        if eof {
            break;
        }
        mem[mem_address as usize] = two_u8_to_16(&buffer);
        mem_address += 1;
    }

}

fn read_image(mem: &mut[u16], image_path: String) -> i32 {
    let file = match File::open(image_path) {
        Ok(file) => file,
        Err(_) => return 0,
    };
    read_image_file(mem, file);
    return 1;
}

fn swap16(x: u16) -> u16 {
    // swap endianness
    return (x << 8) | (x >> 8);
}

fn and(instr: u16, reg: &mut[u16]) {
    // destination register (DR)
    let dr = extract(instr, 9, 0x7);
    // first operand (SR1)
    let sr1 = extract(instr, 6, 0x7);
    // the immediate mode flag
    let imm_flag = extract(instr, 5, 0x1);

    if imm_flag != 0 {
        // zero out all but first five bits
        // before passing into sign_extend
        let imm5 = sign_extend(instr & 0x1F, 5);
        reg[dr] = reg[sr1] & imm5;
    } else {
        let r2 = extract(instr, 0, 0x7);
        reg[dr] = reg[sr1] & reg[r2]
    }

    update_flags(reg, dr);
}

fn branch(instr: u16, reg: &mut[u16]) {
    let pc_offset = sign_extend(instr & 0x1ff, 9);
    let cond_flag = extract(instr, 9, 0x7) as u16;
    if (cond_flag & reg[R::COND as usize]) != 0 {
        reg[R::PC as usize] = reg[R::PC as usize].wrapping_add(pc_offset);
    }
}

fn jump(instr: u16, reg: &mut[u16]) {
    let base_reg = extract(instr, 6, 0x7);
    reg[R::PC as usize] = reg[base_reg];
}

fn jump_register(instr: u16, reg: &mut[u16]) {
    reg[R::R7 as usize] = reg[R::PC as usize];
    let flag = extract(instr, 11, 0x1);
    if flag == 0 {
        jump(instr, reg);
    } else {
        let pc_offset = sign_extend(instr & 0x7ff, 11);
        reg[R::PC as usize] = reg[R::PC as usize].wrapping_add(pc_offset);
    }
}

fn sign_extend(x: u16, bit_count: i32) -> u16 {
    // `(x >> (bit_count - 1)) & 1` will be
    // non zero if the number is negative in two's complement,
    // i.e. has a leading `1`, otherwise it be zero
    if ((x >> (bit_count - 1)) & 1) != 0 {
        // If the number is negative
        //
        return x | 0xFFFF << bit_count;
    }
    return x;
}



fn update_flags(reg: &mut[u16], r: usize) {
    if reg[r] == 0 {
        reg[R::COND as usize] = FL::ZRO as u16;
    } else if (reg[r] >> 15) != 0 {
        reg[R::COND as usize] = FL::NEG as u16;
    } else {
        reg[R::COND as usize] = FL::POS as u16;
    }
}



fn main() {

    // initialize variables
    const UINT16_MAX: usize = u16::max_value() as usize;
    let mut memory: [u16; UINT16_MAX] = [0; UINT16_MAX];
    let mut reg: [u16; R::COUNT as usize] = [0; R::COUNT as usize];
    let stdin = 0; // couldn't get std::os::unix::io::FromRawFd to work
                   // on /dev/stdin or /dev/tty
    let termios = Termios::from_fd(stdin).unwrap();
    let mut new_termios = termios.clone();  // make a mutable copy of termios
                                            // that we will modify

    // get cli args
    // fail if no args
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);

    if args.len() < 2 {
        println!("Enter path to image file");
        std::process::exit(2);
    }

    // load into memoryrust
    if read_image(&mut memory, args[1].clone()) == 0 {
        println!("failed to load image");
        std::process::exit(1);
    }

    // need a way to reenable input buffering on interrupt
    // signal(SIGINT, handle_interrupt);
    disable_input_buffering(&mut new_termios, stdin);


    const PC_START: u16 = 0x3000;
    reg[R::PC as usize] = PC_START;
    loop {

        let instr: u16 = mem_read(&mut memory, reg[R::PC as usize]);
        reg[R::PC as usize] += 1;
        let op_bits: u16 = instr >> 12;

        match FromPrimitive::from_u16(op_bits) {
            Some(OP::ADD)  => add(instr, &mut reg),
            Some(OP::AND)  => and(instr, &mut reg),
            Some(OP::NOT)  => not(instr, &mut reg),
            Some(OP::BR )  => branch(instr, &mut reg),
            Some(OP::JMP)  => jump(instr, &mut reg),
            Some(OP::JSR)  => jump_register(instr, &mut reg),
            Some(OP::LD )  => load(&mut memory, instr, &mut reg),
            Some(OP::LDI)  => load_indirect(&mut memory, instr, &mut reg),
            Some(OP::LDR)  => load_register(&mut memory, instr, &mut reg),
            Some(OP::LEA)  => load_effective_address(instr, &mut reg),
            Some(OP::ST)   => store(&mut memory, instr, &mut reg),
            Some(OP::STI)  => store_indirect(&mut memory, instr, &mut reg),
            Some(OP::STR)  => store_register(&mut memory, instr, &mut reg),
            Some(OP::TRAP) => match FromPrimitive::from_u16(instr & 0xFF) {
                Some(TRAP::GETC)  => trap_getc(&mut reg),
                Some(TRAP::OUT)   => trap_out(&mut reg),
                Some(TRAP::PUTS)  => trap_puts(&mut memory, &mut reg),
                Some(TRAP::IN)    => trap_in(&mut reg),
                Some(TRAP::PUTSP) => trap_putsp(&mut memory, &mut reg),
                Some(TRAP::HALT)  => { println!("Halt"); break; },
                _                 => panic!("Could parse trap code from {:b}", instr & 0xff)
            },
            _             => panic!("Could parse an Opcode from {:b}", op_bits)
        }
    }

    // Shutdown
    restore_input_buffering(termios, stdin);
}
