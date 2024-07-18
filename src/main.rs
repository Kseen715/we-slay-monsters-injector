use std::collections::HashMap;
use process_memory::{Architecture, Memory, DataMember, Pid, ProcessHandleExt, TryIntoProcessHandle};
use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::HANDLE;
use sysinfo::System;

fn get_pid(process_name: &str) -> u32 {
    unsafe {
        let snapshot: HANDLE = CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS,
            0);
        if snapshot == null_mut() {
            return 0;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return 0;
        }

        let target_name = CString::new(process_name).unwrap();

        loop {
            let exe_file = CStr::from_ptr(entry.szExeFile.as_ptr());
            if exe_file == target_name.as_c_str() {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
            if Process32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        0
    }
}

fn get_module_base_address(pid: u32, module_name: &str) -> u64 {
    unsafe {
        let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == null_mut() {
            return 0;
        }

        let mut entry: MODULEENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        if winapi::um::tlhelp32::Module32First(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return 0;
        }

        let target_name = CString::new(module_name).unwrap();

        loop {
            let module_file = CStr::from_ptr(entry.szModule.as_ptr());
            if module_file == target_name.as_c_str() {
                CloseHandle(snapshot);
                return entry.modBaseAddr as u64;
            }
            if winapi::um::tlhelp32::Module32Next(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        0
    }
}

    use process_memory::*;

/*
Reads memory from the process with the given PID at the given address.

# Arguments
* `pid` - The process ID of the target process.
* `address` - The address to read from.

# Returns
The value read from the target process's memory.
*/
fn read_memory<T: Copy>(pid: u32, address: u64) -> T {
    let process_handle = pid.try_into_process_handle().unwrap();
    let mut member = DataMember::<T>::new(process_handle);
    member.set_offset(vec![address as usize]);
    unsafe {
        member.read().unwrap()
    }
}

/*
Writes the given value to the process with the given PID at the given address.

# Arguments
* `pid` - The process ID of the target process.
* `address` - The address to write to.
* `value` - The value to write.
*/
fn write_memory<T: Copy>(pid: u32, address: u64, value: T) {
    let process_handle = pid.try_into_process_handle().unwrap();
    let mut member = DataMember::<T>::new(process_handle);
    member.set_offset(vec![address as usize]);
    member.write(&value).unwrap();
}


fn main() -> std::io::Result<()> {
    let pid = get_pid("weslaymonsters.exe");
    println!("PID: {}", pid);

    let base_address = get_module_base_address(pid, "weslaymonsters.exe");
    println!("Base Address: {:#x}", base_address);
    

    let process_handle = pid.try_into_process_handle()?;
    println!("Process Handle: {:?}", process_handle);

    let mut game_global_gold = DataMember::<u32>::new(process_handle);
    game_global_gold.set_offset(vec![0x27F1CE34]);
    

    unsafe {
        println!("Game Points: {:?}", game_global_gold.read()?);
    }

    // Get system RAM size using sysinfo crate
    let mut system = System::new_all();
    system.refresh_all();
    let ram_size = system.total_memory();

    println!("System RAM size: {} bytes", ram_size);



    
    // Function to scan memory for the known HP value
    fn scan_memory_for_i32(process_handle: &ProcessHandle, base_address: u64, known_value: u32, known_addresses: Vec<u64>) -> Vec<u64> {
        let mut addresses: Vec<u64> = Vec::new();
        addresses.reserve(200000);

        if known_addresses != Vec::new() {
            println!("Known addresses: {:?}", known_addresses.len());
            // Search among known addresses
            let mut buffer: Vec<u8> = vec![0u8; 4]; // Buffer to store the read values
            let start_time = std::time::Instant::now(); // Start the timer
            for current_address in known_addresses {
                match process_handle.copy_address(current_address.try_into().unwrap(), &mut buffer) {
                    Ok(_) => {
                        let value = u32::from_ne_bytes(buffer.clone().try_into().unwrap());
                        // println!("Value: {} ?= {}", value, known_value);
                        if value == known_value {
                            addresses.push(current_address);
                        }

                    }
                    Err(_) => {}
                }


            }
            let end_time = start_time.elapsed(); // Stop the timer
            println!("[DEBUG] Search time: {:?}", end_time); // Log the search time
            return addresses;
        }
        
        let mem_cap = 0xffffffff; // Memory capacity to scan
        let buffer_size = 0x10000; // Buffer size to read from memory
        let mut buffer: Vec<u8> = vec![0u8; buffer_size]; // Buffer to store the read values
        let start_time = std::time::Instant::now(); // Start the timer
    
        let mut current_address = base_address;
        while current_address < base_address + mem_cap {
            match process_handle.copy_address(current_address.try_into().unwrap(), &mut buffer) {
                Ok(_) => {
                    for offset in (0..buffer_size).step_by(4) {
                        let value = u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap());
                        if value == known_value {
                            addresses.push(current_address + offset as u64);
                        }
                    }
                }
                Err(_) => {}
            }
            current_address += buffer_size as u64;
        }
    
        let end_time = start_time.elapsed(); // Stop the timer
        println!("[DEBUG] Search time: {:?}", end_time); // Log the search time
        addresses
    }
    


    println!("Input current HP value: ");
    let mut input: String = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let known_hp_value: u32 = input.trim().parse().unwrap();

    // First scan
    let first_scan_addresses: Vec<u64> = scan_memory_for_i32(&process_handle, base_address, known_hp_value, Vec::new());
    println!("First scan found addresses: {:?}", first_scan_addresses.len());
    
    println!("Input new HP value: ");    
    let mut input: String = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let known_hp_value: u32 = input.trim().parse().unwrap();

    
    // Second scan to confirm the address
    let second_scan_addresses: Vec<u64> = scan_memory_for_i32(&process_handle, base_address, known_hp_value, first_scan_addresses);
    println!("Second scan found addresses: {:?}", second_scan_addresses.len());

    if second_scan_addresses.len() < 4 {
        for address in second_scan_addresses.clone() {
            println!("[DEBUG] offset_hp: {:#X}: {:#X}", address, read_memory::<u32>(pid, address));
        }
    }

    let offset_game_hp: u64 = second_scan_addresses[0];

    // dict
    let mut offsets: HashMap<String, u64> = HashMap::new();
    offsets.insert("hp".to_string(), offset_game_hp);
    offsets.insert("poison".to_string (), offset_game_hp - 0x60);
    offsets.insert("defense".to_string(), offset_game_hp - 0x20);
    offsets.insert("hp_max".to_string(), offset_game_hp - 0x4);
    offsets.insert("luck".to_string(), offset_game_hp + 0x20);
    offsets.insert("intelligence".to_string(), offset_game_hp + 0x40);
    offsets.insert("strength".to_string(), offset_game_hp + 0x60);
    offsets.insert("crit_chance".to_string(), offset_game_hp + 0xA0);
    offsets.insert("xp".to_string(), offset_game_hp + 0xC0);
    offsets.insert("gold".to_string(), offset_game_hp + 0xE0);
    offsets.insert("spikes".to_string(), offset_game_hp + 0x100);


    println!("HP: {}/{}", 
        read_memory::<u32>(pid, offsets["hp"]) as u32, 
        read_memory::<u32>(pid, offsets["hp_max"]) as u32);
    println!("XP: {}", read_memory::<u32>(pid, offsets["xp"]) as u32);
    println!("Gold: {}", read_memory::<u32>(pid, offsets["gold"]) as u32);
    println!("Strength: {}", read_memory::<u32>(pid, offsets["strength"]) as u32);
    println!("Intelligence: {}", read_memory::<u32>(pid, offsets["intelligence"]) as u32);
    println!("Defense: {}", read_memory::<u32>(pid, offsets["defense"]) as u32);
    println!("Poison: {}", read_memory::<u32>(pid, offsets["poison"]) as u32);
    println!("Luck: {}", read_memory::<u32>(pid, offsets["luck"]) as u32);
    println!("Spikes: {}", read_memory::<u32>(pid, offsets["spikes"]) as u32);
    println!("Crit Chance: {}", read_memory::<u32>(pid, offsets["crit_chance"]) as u32);

    Ok(())
}