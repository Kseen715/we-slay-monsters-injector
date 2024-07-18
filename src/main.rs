use std::collections::HashMap;
use process_memory::{Architecture, Memory, DataMember, Pid, ProcessHandleExt, TryIntoProcessHandle};
use std::ffi::{CStr, CString};
use std::ptr::{null, null_mut};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32};
use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::HANDLE;

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


fn main() -> std::io::Result<()> {
    let pid = get_pid("weslaymonsters.exe");
    println!("PID: {}", pid);

    let base_address = get_module_base_address(pid, "weslaymonsters.exe");
    println!("Base Address: {:#x}", base_address);
    
    use process_memory::*;
    let process_handle = pid.try_into_process_handle()?;
    println!("Process Handle: {:?}", process_handle);

    let mut game_global_gold = DataMember::<u32>::new(process_handle);
    game_global_gold.set_offset(vec![0x27F1CE34]);
    

    unsafe {
        println!("Game Points: {:?}", game_global_gold.read()?);
    }

    use std::thread;
    use std::time::Duration;
    
    // Read memory of the game to calculate current offset of HP
    let known_hp_value = 100; // Example known in-game HP value
    
    // Function to scan memory for the known HP value
    fn scan_memory_for_int32_value(process_handle: &ProcessHandle, base_address: u64, known_value: u32) -> Vec<u64> {
        let mut addresses = Vec::new();
        addresses.reserve(10000);
        let mut buffer = vec![0u8; 4]; // Buffer to store the read value
        for address in (base_address..base_address + 0xF000000).step_by(4) {
            match process_handle.copy_address(address.try_into().unwrap(), &mut buffer) {
                Ok(_) => {
                    let value = u32::from_ne_bytes(buffer.clone().try_into().unwrap());
                    if value == known_value {
                        addresses.push(address);
                    }
                }
                Err(_) => {}
            }
 
            let value = u32::from_ne_bytes(buffer.clone().try_into().unwrap());
            if value == known_value {
                addresses.push(address);
            }
        }
        addresses
    }
    

    println!("Input current HP value: ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let known_hp_value: u32 = input.trim().parse().unwrap();

    // First scan
    let first_scan_addresses = scan_memory_for_int32_value(&process_handle, base_address, known_hp_value);
    println!("First scan found addresses: {:?}", first_scan_addresses.len());
    
    println!("Input new HP value: ");    
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let known_hp_value: u32 = input.trim().parse().unwrap();

    
    // Second scan to confirm the address
    let second_scan_addresses = scan_memory_for_int32_value(&process_handle, base_address, known_hp_value);
    println!("Second scan found addresses: {:?}", second_scan_addresses.len());
    
    // Find common addresses between the two scans
    let common_addresses: Vec<u64> = first_scan_addresses
        .into_iter()
        .filter(|addr| second_scan_addresses.contains(addr))
        .collect();
    
    if !common_addresses.is_empty() {
        let offset = common_addresses[0] - base_address;
        println!("Confirmed HP value at address, Offset: {:#x}", offset);
        println!("Count: {}", common_addresses.len());
    } else {
        println!("No common addresses found in the two scans.");
    }

    Ok(())
}