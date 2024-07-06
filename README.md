# MABEL: <u>M</u>alware Analysis Benchmark for Efficient Artificial Intelligence Modeling and Machine Learning

Welcome to the MABEL malware analysis dataset release for machine learning and AI modeling. 

This is our initial dataset release. More releases will be added here shortly. 

Datatable Description

| Feature   | Description | Example Data |
| --------  | ----------- | ------------ |
| sha256_hash	| sha-256 hash of the binary file	| 04195d9d2e4623d9e3818b60c00f5a57ce593441ab137c34c4368eda8b217944 |
 | clam_av_scan_results | results of clam-av scan of the binary. Clam-av is updated prior to scanning the binary. | Win.Malware.Delf-6737076-0 | 
 | yara_malware | yara_malware scan results  | suspicious_packer_section | 
 | family_name | name of malware family (if malware is attributed to a malware family) | Example_Family | 
 | sample_name | name of the malware analyzed | 04195d9d2e4623d9e3818b60c00f5a57ce593441ab137c34c4368eda8b217944 | 
 | md5_hash | md5 hash of the binary file | acd322299c4614f69147dc7254fe8c96 | 
 | sha1_hash | sha-1 hash of the binary file | 9271893e87ee85fa8ad476e4138aace1a10cf70c | 
 | sha224_hash | sha-224 hash of the binary file | fc841641134839c87d027d9446bc598f7552a91c0596ad53e287fae8 | 
 | sha384_hash | sha-384 hash of the binary file | a0d1e2c658b909f6b3e60754160e5e794521d0b4b21da7636fd6fb9e3c7d49ea6b6697fa989a99a3f1ea2ffefeb40a31 | 
 | sha512_hash | sha-512 hash of the binary file | 0cc4b3be4c2d9b9e42bc803457db2102a7baf4097d03a68e69b162100aedb6aa32052bd9908a6ce16a32b606e9e0a6f722da64557e47e94ff03e7496a7516800 | 
 | ssdeep | ssdeep similarity scan of the binary file | 24576:TrIZh50bPfJa1BWeA64Uv5WGdxC3uwvf8s+qp1nMk+0EEIWGyMlX38E1GOIBJiLB:T8H50bPEGUHxC3uW8sdbMOIvyaX38E1v | 
 | imphash | import hash used to identify similarity binaries by hashing their import functions | 9973fdd4b86d866b3faa39fa66cf7e0a | 
 | trid | file identification using TrID database | 40.8% (.CPL) Windows Control Panel Item (generic); 19.2% (.EXE) UPX compressed Win32 Executable; 18.8% (.EXE) Win32 EXE Yoda's Crypter; 7.4% (.EXE) Win64 Executable (generic); 4.6% (.DLL) Win32 Dynamic Link Library (generic) | 
 | file_size | file size of binary (in human readable form) | 1401 kB | 
 | binary_file_size | raw size of binary in bytes | 1400832 | 
 | time_stamp | extracted binary creation date based on timestamp | 2023:04:19 06:42:01+00:00 | 
 | time_date_stamp | extracted binary creation date based on timestamp | 0x643F8D39 [Wed Apr 19 06:42:01 2023 UTC] | 
 | file_modification_date_time | timestamp of binary's last file modification | 2023:04:19 22:14:24+00:00 | 
 | file_type_1 | binary file type (verbose) | PE32 executable (GUI) Intel 80386  for MS Windows  UPX compressed | 
 | file_type_2 | binary file type | Win32 EXE | 
 | binary_class | binary classification with architecture | PE32 | 
 | binary_type | binary type specification | pe | 
 | bits_x64_x32 | indicates 32/64 bit binary architecture | 32 | 
 | machine_architecture | machine architecture to execute binary | i386 | 
 | os | operating system specified to execute binary | windows | 
 | file_type_extension | file extension associated to binary | exe | 
 | subsystem_version | version of binary subsystem | 4 | 
 | summary_architecture | summary of architecture preferred to execute binary | IMAGE_FILE_MACHINE_I386 | 
 | summary_subsystem | subsystem preferred to execute binary | IMAGE_SUBSYSTEM_WINDOWS_GUI | 
 | summary_detected_languages | languages detected in the binary | Russian - Russia | 
 | entropy(min=0.0; max=8.0) | entropy of the entire binary | 6.419568 | 
 | execution_section_name | name of the section containing execution code analyzed by this framework | upx0 | 
 | execution_section_entropy_of_assembly_instructions | entropy of assembly instructions (mnemonic + operands) from first code section containing executable code within binary | 4.655806328 | 
 | execution_section_entropy_of_machine_code(min=0.0; max=8.0) | entropy of machine code (raw bytes) from first code section containing executable code within binary | 2.9832 | 
 | image_base | binary's preferred virtual base address where the PE image should be loaded in memory | 0x400000 | 
 | address_of_entry() | virtual address to beginning of binary's executable code, i.e., start() or entry() | 0x401060 | 
 | address_of_main() | derived virtual address to binary's main() | 0x403d90 | 
 | execution_start_address | address of start() (also referred to as entry) - this should match address_of_entry | 0x401060 | 
 | execution_end_address | virtual address where final execution instruction can be found (within the first executable section of the binary, e.g., .text) | 0x40437c | 
 | execution_size_bytes | size of first executable section within the binary analyzed by this framework i.e., size of .text | 13085 | 
 | initialized_data_size | size of initialized data section | 4096 | 
 | count_unique_mnemonic | total number of unique mnemonics accumulated from deep inspection of binary's disassembly code. NOTE: these counts are accumulated from analyzing the first complete section with executable code e.g., .text | 182 | 
 | count_master_function_call_listing | total number of function  invocations via [call] mnemonic  accumulated from deep inspection of binary's disassembly code.  | 1107 | 
 | count_function_call_listing_via_prologue_analysis | total number of functions  derived  from analyzing function prologues during deep inspection of binary's disassembly code .  | 845 | 
 | count_function_call_listing_via_immediate_address | total number of functions  derived  by analyzing destination address of each branch statement that lands in a new function prologue. This is derived during deep inspection of binary's disassembly code .  | 921 | 
 | count_function_call_listing_via_data_segment_register | total number of functions  derived  by analyzing destination address of each function call invocation that references the data segment as part of the destination address.  This is commonly where we can discover Import Library Function calls.  This is derived during deep inspection of binary's disassembly code.  | 139 | 
 | count_function_call_listing_via_code_segment_register | total number of functions  derived  by analyzing destination address of each function call invocation that references the code segment as part of the destination address.  This is commonly used to jump to different locations within executable code within the binary. This is derived during deep inspection of binary's disassembly code.  | 0 | 
 | count_function_call_listing_via_direct_register | total number of functions  derived  by analyzing destination address of each function call invocation that references a main register as part of the destination address.  This is commonly used to reference a variable from memory. This is derived during deep inspection of binary's disassembly code.  | 5 | 
 | count_function_call_listing_via_indirect_address | total number of functions  derived  by analyzing destination address of each function call invocation that references a main register as part of the destination address.  This is commonly used to calculate an offset to a memory region (e.g. array indexing). This is derived during deep inspection of binary's disassembly code.  | 27 | 
 | count_ret_addresses_via_epilogue | total number of functions  derived by identifying final ret from each function's epilogue. This is derived during deep inspection of binary's disassembly code.  | 1485 | 
 | count_instruction_lines | total number of instructions from the binary's disassembly code | 90557 | 
 | count_NOPS | total number of NOPs identified during deep inspection of binary's disassembly code.  | 895 | 
 | count_INT_OVERFLOW | total number of interrupts identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_INTn | total number of interrupts beyond INT 0, 1, 2, 3 identified during deep inspection of binary's disassembly code.  | 5 | 
 | count_INT0 | total number of INT 0 interrupt identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_INT1 | total number of INT 1 interrupt identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_INT2 | total number of INT 2 interrupt identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_INT3 | total number of INT 3 interrupt identified during deep inspection of binary's disassembly code.  | 3699 | 
 | count_IRET | total number of interrupt return commands identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_HLT | total number of halt interrupt commands identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_BND_CALL | total number of bound interrupt commands identified during deep inspection of binary's disassembly code. This usually occurs for indirect function invocation where target address is determined during runtime | 1 | 
 | count_BND_RET | total number of bound return commands identified during deep inspection of binary's disassembly code.  | 8 | 
 | count_BND_JMP_UNCONDITIONAL | total number of bounded unconditional jump commands identified during deep inspection of binary's disassembly code.  | 2 | 
 | count_BND_JXX_CONDITIONAL | total number of bounded conditional jump commands identified during deep inspection of binary's disassembly code.  | 2 | 
 | count_branching_unconditional_JMP | total number of unconditional jump commands identified during deep inspection of binary's disassembly code.  | 1877 | 
 | count_branching_conditional_JXX | total number of conditional jump commands identified during deep inspection of binary's disassembly code.  | 7721 | 
 | count_SYSCALL | total number of syscall invocations identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_SYSRET | total number of sys_ret commands identified during deep inspection of binary's disassembly code.  | 0 | 
 | count_ENTER | total number of enter prologue commands identified during deep inspection of binary's disassembly code.  | 1 | 
 | count_LEAVE | total number of LEAVE epilogue commands identified during deep inspection of binary's disassembly code.  | 11 | 
 | count_TEST | total number of test commands identified during deep inspection of binary's disassembly code.  | 3729 | 
 | count_CMP | total number of cmp  commands identified during deep inspection of binary's disassembly code.  | 3789 | 
 | count_XOR | total number of exclusive OR commands identified during deep inspection of binary's disassembly code.  | 2020 | 
 | count_CALL | redundancy: total number of [call] function invocation commands identified during deep inspection of binary's disassembly code.  | 5688 | 
 | count_RET | redundancy: total number of [ret] function invocation commands identified during deep inspection of binary's disassembly code.  | 1477 | 
 | count_ADD | total number of [add] commands identified during deep inspection of binary's disassembly code.  | 2807 | 
 | count_SUB | total number of [sub] commands identified during deep inspection of binary's disassembly code.  | 2929 | 
 | count_MUL | total number of [mul] commands identified during deep inspection of binary's disassembly code.  | 29 | 
 | count_DIV | total number of [div] commands identified during deep inspection of binary's disassembly code.  | 36 | 
 | count_CDQ | total number of [cdq] commands identified during deep inspection of binary's disassembly code.  | 40 | 
 | count_LEA | total number of [lea] commands identified during deep inspection of binary's disassembly code.  | 6170 | 
 | count_MOV | total number of [mov] commands identified during deep inspection of binary's disassembly code.  | 22799 | 
 | count_AND | total number of [and] commands identified during deep inspection of binary's disassembly code.  | 791 | 
 | count_OR | total number of [or] commands identified during deep inspection of binary's disassembly code.  | 642 | 
 | count_PUSH | total number of [push] commands identified during deep inspection of binary's disassembly code.  | 12915 | 
 | count_POP | total number of [pop] commands identified during deep inspection of binary's disassembly code.  | 4168 | 
 | import_functions | lists import functions for each library | [ADVAPI32.DLL]  RegCloseKey RegCreateKeyExA RegFlushKey RegOpenKeyExA RegQueryValueExA RegSetValueExA [KERNEL32.DLL]  CloseHandle CopyFileA CreateFileA CreateMutexA DeleteFileA ExitProcess FileTimeToDosDateTime FileTimeToLocalFileTime FindClose FindFirstFileA FindNextFileA FreeLibrary GetCommandLineA GetCurrentThreadId GetFileSize GetFileType GetLastError GetModuleFileNameA GetModuleHandleA GetProcessHeap GetStdHandle GetWindowsDirectoryA HeapAlloc HeapFree HeapReAlloc LocalAlloc RaiseException ReadFile RtlUnwind SetEndOfFile SetFilePointer TlsGetValue TlsSetValue UnhandledExceptionFilter WriteFile [USER32.DLL]  CharNextA  | 
 | count_import_functions | provides count of total import functions | 42 | 
 | packer_1 | identifies the type of packer used for this sample (if applicable) - by the first packer analysis routine used in this framework | UPX(1.24)[NRV brute] | 
 | packer_2 | identifies the type of packer used for this sample (if applicable) - by the second packer analysis routine used in this framework | BobSoft Mini Delphi -> BoB / BobSoft | 
 | peid | identifies packers or compilers using PEiD ("Portable Executable Identifier") | UPX -> www.upx.sourceforge.net; 1 | 
 | binary_overlay_likely_packed | identifies if entropy of binary is indicative of packed code | FALSE | 
 | yara_peid | lists results from yara_peid scan | Borland_Delphi_40_additional; Microsoft_Visual_Cpp_v50v60_MFC; Borland_Delphi_30_additional; Borland_Delphi_30_; Borland_Delphi_Setup_Module; Borland_Delphi_40; Borland_Delphi_v40_v50; BobSoft_Mini_Delphi_BoB_BobSoft_additional; Borland_Delphi_v30; Borland_Delphi_DLL | 
 | yara_packer | lists results from yara_packer scan | BobSoftMiniDelphiBoBBobSoft | 
 | suspicious_overlay_data_bytes | counts the number of bytes in the data overlay that appear to be suspicious | 1269760 | 
 | suspicious_overlay_data_offset | provides offset to the data overlay that appears to be suspicious | 0x20000 | 
 | binary_is_possibly_compressed_encrypted_packed | indicates if the binary is detected to be compressed, encrypted, or packed | FALSE | 
 | yara_apt | lists results from from yara_apt scan | apt28_win_zebrocy_golang_loader_modified | 
 | yara_pos | lists results from from yara_pos scan | - | 
 | yara_anti_debug_anti_vm | lists results from from yara_anti_debug_anti_vm scan | SEH_Save; SEH_Init; anti_dbg | 
 | yara_capabilities | lists results from from yara_capabilities scan | escalate_priv; win_mutex; win_registry; win_token; win_files_operation; domain; IP; Misc_Suspicious_Strings; url | 
 | yara_compiler_signatures | lists results from from yara_compiler_signatures scan | IsPE32; IsWindowsGUI; HasOverlay; borland_delphi | 
 | yara_crypto | lists results from from yara_crypto scan | Big_Numbers1; Delphi_CompareCall; Delphi_Copy | 
 | yara_maldocs | lists results from from yara_maldocs scan | powershell | 
 | yara_miners | lists results from from yara_miners scan | MINER_monero_mining_detection | 
 | yara_operation_blockbuster | lists results from from yara_operation_blockbuster scan | WhiskeyAlfa | 
 | yara_pentest_toolkits | lists results from from yara_pentest_toolkits scan | - | 
 | yara_ransomware | lists results from from yara_ransomware scan | HKTL_NET_NAME_ConfuserEx | 
 | yara_rat | lists results from from yara_rat scan | UPX | 
 | yara_stealer | lists results from from yara_stealer scan | STEALER_Lokibot | 
 | yara_webshells | lists results from from yara_webshells scan | - | 
 | compiler_details_1 | lists detected compiler details | Borland Delphi(6-7 or 2005) | 
 | compiler_details_2 | lists additional details of compiler details | Microsoft Visual C/C++(19.00.23026)[LTCG/C++] | 
 | linker | identifies details about the linker used for this binary  | Turbo Linker(2.25* Delphi)[GUI32] | 
 | tool | identifies the tool (e.g., IDE) used to create and modify this binary | Visual Studio(2015) | 
 | metadata_filetype | provides the file type (e.g., exe or dll) identified from the binary's metadata | exe (application/x-msdownload) | 
 | mime_type | identifies the MIME type of this binary | DOS/Windows executable | 
 | endianness | identifies byte order for this binary: little/big endian | little | 
 | programming_language | identifies programming language used to code the binary | c | 
 | summary_debug_artifacts | identifies location of debugging symbols for this binary (if applicable) | C:\Users\admin\Desktop\new version with NO UAC\Release\Win32Project9.pdb | 
 | stack_canary_enabled | identifies if stack canaries are used to protect memory corruption while executing this binary | TRUE | 
 | safe_seh_enabled | identifies if safe structured exception handling is enabled | TRUE | 
 | aslr_enabled | identifies if address space layout randomization is enabled | TRUE | 
 | dep_enabled | identifies if data execution prevention is enabled | TRUE | 
 | cfg_enabled | identifies if control flow guard is enabled | FALSE | 
 | code_sections | identifies the sections that contain code and data for this binary | .data .rdata .reloc .rsrc .text .tls | 
 | code_section_sizes | identifies the sections that contain code and data for this binary along with respective size (in bytes) of each section | .data(2800) .rdata(10200)  .reloc(4200)  .rsrc(400)  .text(43600)  .tls(200)  | 
 | entropy_per_section | identifies entropy of each section in the binary | PE Header (6.99707: packed); UPX0 (2.9832: not packed); UPX1 (3.44151: not packed); .rsrc (0.179721: not packed); Overlay (6.72157: packed) | 
 | number_sections | identifies the number of code sections found in this binary | 6 | 
 | data_directories | identifies the data directories in this binary | basereloc debug iat import load_config resource tls | 
 | data_directory_sizes | identifies the data directories in this binary along with each respective directory's file size (in hex) | basereloc(0x413c) debug(0x70)  iat(0x264)  import(0x8c)  load_config(0x40)  resource(0x348)  tls(0x18)  | 
 | number_data_directories | identifies number of data directories in this binary | 7 | 
 | base_address | identifies the virtual base address where this binary is loaded | 0x400000 | 
 | canary | separate process identifying if canary is used to protect the binary | TRUE | 
 | return_address_protection_enabled | identifies if protections for return address contamination is enabled | FALSE | 
 | compressed_data_checksum | identifies the checksum of compressed data | 0x00061971 | 
 | crypto | indicates presence of cryptographic functions | FALSE | 
 | path_to_dbg_PDB_file | secondary process to identify path to debug symbols (if applicable) | C:\Users\admin\Desktop\new version with NO UAC\Release\Win32Project9.pdb | 
 | binary_contains_executable_have_code | indicates if binary was detected to have executable code | TRUE | 
 | binary_header_checksum | indicates checksum of binary header | 0x00000000 | 
 | binary_globally_unique_identifier_guid | provides the GUID for this binary (useful for tracking) | 7D4161849AC1429B9B32A13BCDEB98711 | 
 | binary_load_address | indicates address of where the binary is loaded in memory (this is often 0x0 until executed dynamically) | 0x0 | 
 | line_numbers_present_in_binary | indicates if line number are present in binary's source code (this is usually false) | FALSE | 
 | local_symbols_present_lsyms | indicates if local debug symbols are present for this binary | FALSE | 
 | data_execution_prevention_nx | secondary function to identify if data execution prevention (NX) is enabled | TRUE | 
 | overlay_present | identifies if an overlay is detected in the binary | TRUE | 
 | code_calling_convention | identifies the calling convention used in the binary's code | cdecl | 
 | position_independent_code_present_pic | identifies if position independent code protection is enabled | TRUE | 
 | relocation_information_present | indicates if relocation information is detected within binary | FALSE | 
 | signed | indicates if the binary was cryptographically signed with a code signing certificate | FALSE | 
 | binary_compiled_with_code_sanitize_features_present | indicates if binary was compiled with code sanitization features (usually false) | FALSE | 
 | binary_is_linked_statically | indicates if the binary is statically linked (meaning all import libraries and functions are attached to the binary) - this is usually false such that the operating system handles loading import libraries dynamically | FALSE | 
 | binary_is_stripped_of_debug_symbols | indicates if the binary is stripped of debug symbols | FALSE | 
 | subsystem_1 | secondary process to identify the subsystem for the binary | Windows GUI | 
 | binary_supports_virtual_address | indicates if the binary supports virtual addressing  | TRUE | 
 | assembly_version | indicates the version of assembly language for this binary | 4.2.5.7 | 
 | builder | identifies information regarding the builder tool used to create the binary | - | 
 | character_set | identifies the character set for this binary | ASCII | 
 | comments_1 | identifies additional comments found within this binary | - | 
 | comments_2 | additional space to identify additional comments found within this binary | Thunder7.9.3.4404 | 
 | company_1 | identifies company information regarding this binary | NVIDIA Corporation | 
 | company_name | identifies company name regarding this binary | Microsoft Corporation | 
 | company_short_name | identifies shortened company name regarding this binary | Microsoft | 
 | compiled_script | identifies if the binary is a compiled script (usually not specified) | - | 
 | version_number | identifies version number regarding this binary | 12.7 | 
 | file_description | identifies binary file description | InstallShield (R) Setup Launcher | 
 | file_flags | specifies flags associated with this binary | Private build  Info inferred  Special build | 
 | file_flags_mask | specifies mask value used to indicate valid bits in file_flags. | 0x058c | 
 | file_permissions | specifies permissions associated to this binary | -rw-r--r-- | 
 | file_version | specifies simplified file version | 1 | 
 | file_version_number | specifies full file version if present in binary | 1.0.0.0 | 
 | image_version | specifies image version | 1 | 
 | internal_build_number | specifies build number used to reference this binary | 158438 | 
 | internal_name | specifies internal names used to reference this binary | Setup | 
 | is_internal_description | specifies details regarding internal description regarding this binary | Setup Launcher Unicode | 
 | is_internal_version | specifies details regarding internal version number regarding this binary | 22.0.347 | 
 | language_code | specifies detected language(s) within this binary | Russian | 
 | language_id | specifies the language identifier detected within this binary | f138284b023200fc74a1957c90eb31f1382702de-refs/heads/master@{#671547} | 
 | last_change | secondary data regarding last change hash of the sample (not always provided) | Copyright 2022 The Chromium Authors. All rights reserved. | 
 | legal_copyright | specifies legal copyright statement regarding this binary | Copyright (C) 2022 | 
 | legal_trademarks_1 | specifies legal trademark details regarding this binary | All Rights Reserved | 
 | legal_trademarks_2 | specifies additional legal trademark details regarding this binary | All Rights Reserved | 
 | legal_trademarks_3 | specifies additional legal trademark details regarding this binary | All Rights Reserved | 
 | object_file_type | specifies type of this binary (usually executable or dynamic link library) | Executable application | 
 | official_build | specifies official build number of this binary | 1 | 
 | original_file_name | specifies original file name for this binary | S6d41.exe | 
 | private_build | specifies private build details regarding this binary | Built by swtools on CNABDC33 on 03/28/13 at 22:07 | 
 | product_name | specifies product name regarding this binary | NVIDIA Smart Maximise Helper Host version 100.03 | 
 | product_short_name | specifies shortened product name regarding this binary | Yandex | 
 | product_version | specifies product version regarding this binary | 1 | 
 | product_version_number | specifies product version number regarding this binary | 1.0.0.0 | 
 | program_id | specifies program identifier regarding this binary | com.embarcadero.SpSInstall | 
 | special_build | specifies if this binary is indicated as a special release | 1082 | 
 | uninitialized_data_size | specifies the size of uninitialized data in this binary | 40960 | 
 | e_magic | PE header identification of the DOS header magic number | 0x5A4D | 
 | e_cblp | PE header identification of the number of bytes in the last page of the binary | 0x50 | 
 | e_cp | PE header identification of the number of pages in this binary | 0x2 | 
 | e_crlc | PE header identification of the number of relocation entries in this binary | 0x0 | 
 | e_cparhdr | PE header identification of the size of the header in paragraphs | 0x4 | 
 | e_minalloc | PE header identification of the minimum number of paragraphs needed | 0xF | 
 | e_maxalloc | PE header identification of the maximum number of extra paragraphs needed | 0xFFFF | 
 | e_ss | PE header identification of the initial (relative) stack segment location | 0x0 | 
 | e_sp | PE header identification of the initial stack pointer value | 0xB8 | 
 | e_csum | PE header identification of the binary checksum | 0x0 | 
 | e_ip | PE header identification of the initial instruction pointer value | 0x0 | 
 | e_cs | PE header identification of the initial (relative) code segment location | 0x0 | 
 | e_lfarlc | PE header identification of the offset to the relocation table | 0x40 | 
 | e_ovno | PE header identification of the overlay number | 0x1A | 
 | e_res | PE header identification of reserved words (usually set to 0x0) | !\xb8\x01L\xcd!Win32\x20.EXE.\x0d\x0a$ | 
 | e_oemid | PE header identification of the OEM version | 0x0 | 
 | e_oeminfo | PE header identification of the OEM version information | 0x0 | 
 | e_res2 | PE header identification of reserved words (for future use) | !\xb8\x01L\xcd!Win32\x20.EXE.\x0d\x0a$ | 
 | e_lfanew | PE header file address specification of the offset to the PE header | 0x100 | 
 | machine | PE header identification of the machine type (x86 or x64) | 0x14C | 
 | number_of_sections | PE header identification of the number of sections in the binary | 0x6 | 
 | size_of_optional_header | PE header identification of the optional header size | 0xE0 | 
 | characteristics | PE header identification of the characteristics flags (specifies various attributes e.g. exe, 64-bit, etc) | 0x818F | 
 | magic | PE header identification of the magic number (e.g., PE32, PE32+) | 0x10B | 
 | major_linker_version | PE header identification of the major version of the linker | 0x2 | 
 | minor_linker_version | PE header identification of the minor  version of the linker | 0x19 | 
 | size_of_code | PE header identification of the size of the code section | 0x3000 | 
 | size_of_initialized_data | PE header identification of the size of initialized data | 0x1000 | 
 | size_of_uninitialized_data | PE header identification of the size of unitialized data | 0xA000 | 
 | address_of_entrypoint | PE header identification of the original entry point | 0x4670 | 
 | base_of_code | PE header identification of the offset to the original entry point | 0xB000 | 
 | base_of_data | PE header identification of the offset to the base of data section | 0xE000 | 
 | section_alignment | PE header identification of the alignment of sections in memory | 0x1000 | 
 | file_alignment | PE header identification of the raw data alignment | 0x200 | 
 | major_operating_system_version | PE header identification of the major version required to execute this binary | 0x4 | 
 | minor_operating_system_version | PE header identification of the minor version required to execute this binary | 0x0 | 
 | major_image_version | PE header specification of the major image version | 0x0 | 
 | minor_image_version | PE header specification of the minor image version | 0x0 | 
 | major_subsystem_version | PE header identifying the major version of the os subsystem required to execute this binary | 0x4 | 
 | minor_subsystem_version | PE header identifying the minor version of the os subsystem required to execute this binary | 0x0 | 
 | reserved1 | PE header element reserved for future use (usually set to 0) | 0x0 | 
 | size_of_image | PE header identification of the image size | 0x20000 | 
 | size_of_headers | PE header identification of the size of all headers | 0x1000 | 
 | checksum | PE header identification of the checksum used to verify the integrity of the binary | 0x23252 | 
 | subsystem_3 | PE header identification of the subsystem required to execute this binary | 0x2 | 
 | dll_characteristics | PE header specification of attributes of a DLL file (e.g., supports ASLR, DEP, etc) | 0x0 | 
 | size_of_stack_reserve | PE header identification of the size of the stack to reserve | 0x100000 | 
 | size_of_stack_commit | PE header identification of the size of the stack to commit | 0x4000 | 
 | size_of_heap_reserve | PE header identification of the heap size to reserve | 0x100000 | 
 | size_of_heap_commit | PE header identification of the heap size to commit | 0x1000 | 
 | loader_flags | PE header reserved for future use (usually set to 0x0) | 0x0 | 
 | number_of_rva_and_sizes | PE header identification of the number of data directory entries | 0x10 | 
 | signature | PE file signature identifying it is a valid executable binary | MZ | 
 | linker_version | PE header identification of the linker version | 2.25 | 
 | machine_hex | PE header identification of the architecture | 0x14c x86 | 
 | number_of_sections_hex | PE header identification of the number of code sections | 6 | 
 | pointer_to_symbol_table_hex | PE header identification of the pointer to the symbol table | 0 | 
 | number_of_symbols_hex | PE header identification of the number of symbols | 0 | 
 | size_of_optional_header_hex | PE header identification of the optional header size | 0xe0 | 
 | characteristics_hex | PE header identification of the binary characteristics | 0x818f RELOCS_STRIPPED  EXECUTABLE_IMAGE | 
 | magic_hex | PE header identification of the architecture of the binary | 0x10b 32-bit executable | 
 | size_of_code_hex | PE header identification of the code size | 0x3000 | 
 | size_of_initialized_data_hex | PE header identification of the initialized data size | 0x1000 | 
 | size_of_uninitialized_data_hex | PE header identification of the uninitialized data size | 0xa000 | 
 | address_of_entrypoint_hex | PE header identification of the original entry point | 0x4670 | 
 | base_of_code_hex | PE header identification of the code base address | 0xb000 | 
 | base_of_data_hex | PE header identification of the data base address | 0xe000 | 
 | image_base_hex | PE header identification of the preferred base address to load the PE image | 0x400000 | 
 | section_alignment_hex | PE header identification of the section alignment | 0x1000 | 
 | file_alignment_hex | PE header identification of the file alignment | 0x200 | 
 | reserved1_hex | PE header element reserved for future use (usually set to 0) | 0 | 
 | size_of_image_hex | PE header identification of the image size | 0x20000 | 
 | size_of_headers_hex | PE header identification of the header size | 0x1000 | 
 | checksum_hex | PE header identification of the checksum used to verify the integrity of the binary | 0x23252 | 
 | subsystem_hex | PE header identification of the subsystem | 2 WINDOWS_GUI | 
 | dll_characteristics_hex | PE header identification of the dll characteristics | 0 | 
 | size_of_stack_reserve_hex | PE header identification of the size of the stack to reserve | 0x100000 | 
 | size_of_stack_commit_hex | PE header identification of the size of the stack to commit | 0x4000 | 
 | size_of_heap_reserve_hex | PE header identification of the size of the heap to reserve | 0x100000 | 
 | size_of_heap_commit_hex | PE header identification of the size of the heap to commit | 0x1000 | 
 | loader_flags_hex | PE header identification of the loader flags | 0 | 
 | number_of_rva_and_sizes_hex | PE header identification of the relative virtual addresses | 0x10 | 
 | machine_decimal | decimal conversion of machine_hex | 332 | 
 | number_of_sections_decimal | decimal conversion of number_of_sections_hex | 3 | 
 | pointer_to_symbol_table_decimal | decimal conversion of pointer_to_symbol_table_hex | 0 | 
 | number_of_symbols_decimal | decimal conversion of number_of_symbols_hex | 0 | 
 | size_of_optional_header_decimal | decimal conversion of size_of_optional_header_hex | 224 | 
 | characteristics_decimal | decimal conversion of characteristics_hex | 33167 | 
 | magic_decimal | decimal conversion of magic_hex | 267 | 
 | size_of_code_decimal | decimal conversion of size_of_code_hex | 12288 | 
 | size_of_initialized_data_decimal | decimal conversion of size_of_initialized_data_hex | 4096 | 
 | size_of_uninitialized_data_decimal | decimal conversion of size_of_uninitialized_data_hex | 40960 | 
 | address_of_entrypoint_decimal | decimal conversion of address_of_entrypoint_hex | 18032 | 
 | base_of_code_decimal | decimal conversion of base_of_code_hex | 45056 | 
 | base_of_data_decimal | decimal conversion of base_of_data_hex | 57344 | 
 | imagebase_decimal | decimal conversion of image_base_hex | 4194304 | 
 | section_alignment_decimal | decimal conversion of section_alignment_hex | 4096 | 
 | file_alignment_decimal | decimal conversion of file_alignment_hex | 512 | 
 | reserved1_decimal | decimal conversion of reserved1_hex | 0 | 
 | size_of_image_decimal | decimal conversion of size_of_image_hex | 131072 | 
 | size_of_headers_decimal | decimal conversion of size_of_headers_hex | 4096 | 
 | checksum_decimal | decimal conversion of checksum_hex | 143954 | 
 | subsystem_decimal | decimal conversion of subsystem_hex | 2 | 
 | dll_characteristics_decimal | decimal conversion of dll_characteristics_hex | 0 | 
 | size_of_stack_reserve_decimal | decimal conversion of size_of_stack_reserve_hex | 1048576 | 
 | size_of_stack_commit_decimal | decimal conversion of size_of_stack_commit_hex | 16384 | 
 | size_of_heap_reserve_decimal | decimal conversion of size_of_heap_reserve_hex | 1048576 | 
 | size_of_heap_commit_decimal | decimal conversion of size_of_heap_commit_hex | 4096 | 
 | loader_flags_decimal | decimal conversion of loader_flags_hex | 0 | 
 | number_of_rva_and_sizes_decimal | decimal conversion of number_of_rva_and_sizes_hex | 16 | 
 | installer | specifies information about the installer for executing this binary (if applicable) | InstallShield(19.6) | 
 | joiner | specifies information about the joiner for executing this binary (if applicable) | - | 
 | operation | specifies information about the operation for executing this binary (if applicable) | MS-DOS(-) | 
 | patcher | specifies information about the patcher for this binary | simple patch(-) | 
 | protector | specifies information about protection technology for this binary | VMProtect(2.XX-3.XX)[Min protection] | 
 | sfx | specifies details regarding self extracting code for this binary | Microsoft Cabinet(11.00.14393.0 (rs1_release.160715-1616)) | 
 | archive | specifies details if this sample is an archive | Microsoft Cabinet File(1.03)[LZX 83.6% 2 files] | 
 | library | specifies details regarding libraries used for this binary (e.g. .NET) | .NET(v4.0.30319) | 
 | .text_in_binary | specifies if [.text] code section was detected in this binary | TRUE | 
 | .data_in_binary | specifies if [.data] code section was detected in this binary | TRUE | 
 | .rsrc_in_binary | specifies if [.rsrc] code section was detected in this binary | TRUE | 
 | .rdata_in_binary | specifies if [.rdata] code section was detected in this binary | TRUE | 
 | .reloc_in_binary | specifies if [.reloc] code section was detected in this binary | FALSE | 
 | .idata_in_binary | specifies if [.idata] code section was detected in this binary | FALSE | 
 | .pdata_in_binary | specifies if [.pdata] code section was detected in this binary | FALSE | 
 | .tls_in_binary | specifies if [.tls] code section was detected in this binary | FALSE | 
 | .bss_in_binary | specifies if [.bss] code section was detected in this binary | FALSE | 
 | .crt_in_binary | specifies if [.crt] code section was detected in this binary | FALSE | 
 | .edata_in_binary | specifies if [.edata] code section was detected in this binary | FALSE | 
 | .gfids_in_binary | specifies if [.gfids] code section was detected in this binary | FALSE | 
 | .symtab_in_binary | specifies if [.symtab] code section was detected in this binary | FALSE | 
 | .xdata_in_binary | specifies if [.xdata] code section was detected in this binary | FALSE | 
 | .ndata_in_binary | specifies if [.ndata] code section was detected in this binary | FALSE | 
 | .itext_in_binary | specifies if [.itext] code section was detected in this binary | FALSE | 
 | .didata.00cfg_in_binary | specifies if [.didata.00cfg] code section was detected in this binary | FALSE | 
 | .imports_in_binary | specifies if [.imports] code section was detected in this binary | FALSE | 
 | .sdata_in_binary | specifies if [.sdata] code section was detected in this binary | FALSE | 
 | .x_in_binary | specifies if [.x] code section was detected in this binary | FALSE | 
 | .upx1_in_binary | specifies if [.upx1] code section was detected in this binary | FALSE | 
 | .upx0_in_binary | specifies if [.upx0] code section was detected in this binary | FALSE | 
 | .didat_in_binary | specifies if [.didat] code section was detected in this binary | FALSE | 
 | .vmp0_in_binary | specifies if [.vmp0] code section was detected in this binary | FALSE | 
 | .vmp1_in_binary | specifies if [.vmp1] code section was detected in this binary | FALSE | 
 | .gehcont_in_binary | specifies if [.gehcont] code section was detected in this binary | FALSE | 
 | .mpress1_in_binary | specifies if [.mpress1] code section was detected in this binary | FALSE | 
 | .mpress2_in_binary | specifies if [.mpress2] code section was detected in this binary | FALSE | 
 | .eh_fram_in_binary | specifies if [.eh_fram] code section was detected in this binary | FALSE | 
 | .cdata_in_binary | specifies if [.cdata] code section was detected in this binary | FALSE | 
 | .code_in_binary | specifies if [.code] code section was detected in this binary | FALSE | 
 | .data2_in_binary | specifies if [.data2] code section was detected in this binary | FALSE | 
 | .text2_in_binary | specifies if [.text2] code section was detected in this binary | FALSE | 
 | .data1_in_binary | specifies if [.data1] code section was detected in this binary | FALSE | 
 | .debug_in_binary | specifies if [.debug] code section was detected in this binary | FALSE | 
 | .init_in_binary | specifies if [.init] code section was detected in this binary | FALSE | 
 | .flat_in_binary | specifies if [.flat] code section was detected in this binary | FALSE | 
 | .keys_in_binary | specifies if [.keys] code section was detected in this binary | FALSE | 
 | .msvcjmc_in_binary | specifies if [.msvcjmc] code section was detected in this binary | FALSE | 
 | .rva_in_binary | specifies if [.rva] code section was detected in this binary | FALSE | 
 | .themida_in_binary | specifies if [.themida] code section was detected in this binary | FALSE | 
 | .vmp2_in_binary | specifies if [.vmp2] code section was detected in this binary | FALSE | 
 | .voltbl_in_binary | specifies if [.voltbl] code section was detected in this binary | FALSE | 
 | .adata_in_binary | specifies if [.adata] code section was detected in this binary | FALSE | 
 | .bin_in_binary | specifies if [.bin] code section was detected in this binary | FALSE | 
 | .sxdata_in_binary | specifies if [.sxdata] code section was detected in this binary | FALSE | 
 | .text1_in_binary | specifies if [.text1] code section was detected in this binary | FALSE | 
 | .textbss_in_binary | specifies if [.textbss] code section was detected in this binary | FALSE | 
 | .0lgfxz_in_binary | specifies if [.0lgfxz] code section was detected in this binary | FALSE | 
 | .l2_in_binary | specifies if [.l2] code section was detected in this binary | FALSE | 
 | .orpc_in_binary | specifies if [.orpc] code section was detected in this binary | FALSE | 
 | .retplne_in_binary | specifies if [.retplne] code section was detected in this binary | FALSE | 
 | .41hfa_in_binary | specifies if [.41hfa] code section was detected in this binary | FALSE | 
 | .6ll_in_binary | specifies if [.6ll] code section was detected in this binary | FALSE | 
 | .7ps_in_binary | specifies if [.7ps] code section was detected in this binary | FALSE | 
 | .ap0x_in_binary | specifies if [.ap0x] code section was detected in this binary | FALSE | 
 | .aspack_in_binary | specifies if [.aspack] code section was detected in this binary | FALSE | 
 | .bedrock_in_binary | specifies if [.bedrock] code section was detected in this binary | FALSE | 
 | .boot_in_binary | specifies if [.boot] code section was detected in this binary | FALSE | 
 | .cfg_in_binary | specifies if [.cfg] code section was detected in this binary | FALSE | 
 | .cwkw_in_binary | specifies if [.cwkw] code section was detected in this binary | FALSE | 
 | .data3_in_binary | specifies if [.data3] code section was detected in this binary | FALSE | 
 | .date1_in_binary | specifies if [.date1] code section was detected in this binary | FALSE | 
 | .ddata_in_binary | specifies if [.ddata] code section was detected in this binary | FALSE | 
 | .enigma1_in_binary | specifies if [.enigma1] code section was detected in this binary | FALSE | 
 | .enigma2_in_binary | specifies if [.enigma2] code section was detected in this binary | FALSE | 
 | .exports_in_binary | specifies if [.exports] code section was detected in this binary | FALSE | 
 | .fleilpb_in_binary | specifies if [.fleilpb] code section was detected in this binary | FALSE | 
 | .gegofon_in_binary | specifies if [.gegofon] code section was detected in this binary | FALSE | 
 | .gufav_in_binary | specifies if [.gufav] code section was detected in this binary | FALSE | 
 | .hidata_in_binary | specifies if [.hidata] code section was detected in this binary | FALSE | 
 | .hky_in_binary | specifies if [.hky] code section was detected in this binary | FALSE | 
 | .hs94nbl_in_binary | specifies if [.hs94nbl] code section was detected in this binary | FALSE | 
 | .i2o_in_binary | specifies if [.i2o] code section was detected in this binary | FALSE | 
 | .idata2_in_binary | specifies if [.idata2] code section was detected in this binary | FALSE | 
 | .irdata_in_binary | specifies if [.irdata] code section was detected in this binary | FALSE | 
 | .iwpd_in_binary | specifies if [.iwpd] code section was detected in this binary | FALSE | 
 | .j_in_binary | specifies if [.j] code section was detected in this binary | FALSE | 
 | .jiisysj_in_binary | specifies if [.jiisysj] code section was detected in this binary | FALSE | 
 | .mpyess2_in_binary | specifies if [.mpyess2] code section was detected in this binary | FALSE | 
 | .mysec10_in_binary | specifies if [.mysec10] code section was detected in this binary | FALSE | 
 | .newiid_in_binary | specifies if [.newiid] code section was detected in this binary | FALSE | 
 | .p59108_in_binary | specifies if [.p59108] code section was detected in this binary | FALSE | 
 | .qqiolo_in_binary | specifies if [.qqiolo] code section was detected in this binary | FALSE | 
 | .qwdfr0_in_binary | specifies if [.qwdfr0] code section was detected in this binary | FALSE | 
 | .rda_in_binary | specifies if [.rda] code section was detected in this binary | FALSE | 
 | .rdat_in_binary | specifies if [.rdat] code section was detected in this binary | FALSE | 
 | .rrth0_in_binary | specifies if [.rrth0] code section was detected in this binary | FALSE | 
 | .rrth1_in_binary | specifies if [.rrth1] code section was detected in this binary | FALSE | 
 | .rrth2_in_binary | specifies if [.rrth2] code section was detected in this binary | FALSE | 
 | .rubutiz_in_binary | specifies if [.rubutiz] code section was detected in this binary | FALSE | 
 | .sbss_in_binary | specifies if [.sbss] code section was detected in this binary | FALSE | 
 | .script_in_binary | specifies if [.script] code section was detected in this binary | FALSE | 
 | .shared_in_binary | specifies if [.shared] code section was detected in this binary | FALSE | 
 | .stub_in_binary | specifies if [.stub] code section was detected in this binary | FALSE | 
 | .sw_in_binary | specifies if [.sw] code section was detected in this binary | FALSE | 
 | .tdata0_in_binary | specifies if [.tdata0] code section was detected in this binary | FALSE | 
 | .tdata1_in_binary | specifies if [.tdata1] code section was detected in this binary | FALSE | 
 | .tdata2_in_binary | specifies if [.tdata2] code section was detected in this binary | FALSE | 
 | .trace_in_binary | specifies if [.trace] code section was detected in this binary | FALSE | 
 | .udata_in_binary | specifies if [.udata] code section was detected in this binary | FALSE | 
 | .upx_in_binary | specifies if [.upx] code section was detected in this binary | FALSE | 
 | .uzp0_in_binary | specifies if [.uzp0] code section was detected in this binary | FALSE | 
 | .uzp1_in_binary | specifies if [.uzp1] code section was detected in this binary | FALSE | 
 | .w_in_binary | specifies if [.w] code section was detected in this binary | FALSE | 
 | .wap2il_in_binary | specifies if [.wap2il] code section was detected in this binary | FALSE | 
 | .wdata_in_binary | specifies if [.wdata] code section was detected in this binary | FALSE | 
 | .wn_in_binary | specifies if [.wn] code section was detected in this binary | FALSE | 
 | .xaq_in_binary | specifies if [.xaq] code section was detected in this binary | FALSE | 
 | .xml_in_binary | specifies if [.xml] code section was detected in this binary | FALSE | 
 | .xu8i_in_binary | specifies if [.xu8i] code section was detected in this binary | FALSE | 
 | .yj_in_binary | specifies if [.yj] code section was detected in this binary | FALSE | 
 | .ywi1hpv_in_binary | specifies if [.ywi1hpv] code section was detected in this binary | FALSE | 
 | .text_size_in_binary | specifies the size of [.text] code section if it was detected in this binary | 8192 | 
 | .data_size_in_binary | specifies the size of [.data] code section if it was detected in this binary | 4096 | 
 | .rsrc_size_in_binary | specifies the size of [.rsrc] code section if it was detected in this binary | 110592 | 
 | .rdata_size_in_binary | specifies the size of [.rdata] code section if it was detected in this binary | 4096 | 
 | .reloc_size_in_binary | specifies the size of [.reloc] code section if it was detected in this binary | 0 | 
 | .idata_size_in_binary | specifies the size of [.idata] code section if it was detected in this binary | 0 | 
 | .pdata_size_in_binary | specifies the size of [.pdata] code section if it was detected in this binary | 0 | 
 | .tls_size_in_binary | specifies the size of [.tls] code section if it was detected in this binary | 0 | 
 | .bss_size_in_binary | specifies the size of [.bss] code section if it was detected in this binary | 0 | 
 | .crt_size_in_binary | specifies the size of [.crt] code section if it was detected in this binary | 0 | 
 | .edata_size_in_binary | specifies the size of [.edata] code section if it was detected in this binary | 0 | 
 | .gfids_size_in_binary | specifies the size of [.gfids] code section if it was detected in this binary | 0 | 
 | .symtab_size_in_binary | specifies the size of [.symtab] code section if it was detected in this binary | 0 | 
 | .xdata_size_in_binary | specifies the size of [.xdata] code section if it was detected in this binary | 0 | 
 | .ndata_size_in_binary | specifies the size of [.ndata] code section if it was detected in this binary | 0 | 
 | .itext_size_in_binary | specifies the size of [.itext] code section if it was detected in this binary | 0 | 
 | .didata.00cfg_size_in_binary | specifies the size of [.didata.00cfg] code section if it was detected in this binary | 0 | 
 | .imports_size_in_binary | specifies the size of [.imports] code section if it was detected in this binary | 0 | 
 | .sdata_size_in_binary | specifies the size of [.sdata] code section if it was detected in this binary | 0 | 
 | .x_size_in_binary | specifies the size of [.x] code section if it was detected in this binary | 0 | 
 | .upx1_size_in_binary | specifies the size of [.upx1] code section if it was detected in this binary | 0 | 
 | .upx0_size_in_binary | specifies the size of [.upx0] code section if it was detected in this binary | 0 | 
 | .didat_size_in_binary | specifies the size of [.didat] code section if it was detected in this binary | 0 | 
 | .vmp0_size_in_binary | specifies the size of [.vmp0] code section if it was detected in this binary | 0 | 
 | .vmp1_size_in_binary | specifies the size of [.vmp1] code section if it was detected in this binary | 0 | 
 | .gehcont_size_in_binary | specifies the size of [.gehcont] code section if it was detected in this binary | 0 | 
 | .mpress1_size_in_binary | specifies the size of [.mpress1] code section if it was detected in this binary | 0 | 
 | .mpress2_size_in_binary | specifies the size of [.mpress2] code section if it was detected in this binary | 0 | 
 | .eh_fram_size_in_binary | specifies the size of [.eh_fram] code section if it was detected in this binary | 0 | 
 | .cdata_size_in_binary | specifies the size of [.cdata] code section if it was detected in this binary | 0 | 
 | .code_size_in_binary | specifies the size of [.code] code section if it was detected in this binary | 0 | 
 | .data2_size_in_binary | specifies the size of [.data2] code section if it was detected in this binary | 0 | 
 | .text2_size_in_binary | specifies the size of [.text2] code section if it was detected in this binary | 0 | 
 | .data1_size_in_binary | specifies the size of [.data1] code section if it was detected in this binary | 0 | 
 | .debug_size_in_binary | specifies the size of [.debug] code section if it was detected in this binary | 0 | 
 | .init_size_in_binary | specifies the size of [.init] code section if it was detected in this binary | 0 | 
 | .flat_size_in_binary | specifies the size of [.flat] code section if it was detected in this binary | 0 | 
 | .keys_size_in_binary | specifies the size of [.keys] code section if it was detected in this binary | 0 | 
 | .msvcjmc_size_in_binary | specifies the size of [.msvcjmc] code section if it was detected in this binary | 0 | 
 | .rva_size_in_binary | specifies the size of [.rva] code section if it was detected in this binary | 0 | 
 | .themida_size_in_binary | specifies the size of [.themida] code section if it was detected in this binary | 0 | 
 | .vmp2_size_in_binary | specifies the size of [.vmp2] code section if it was detected in this binary | 0 | 
 | .voltbl_size_in_binary | specifies the size of [.voltbl] code section if it was detected in this binary | 0 | 
 | .adata_size_in_binary | specifies the size of [.adata] code section if it was detected in this binary | 0 | 
 | .bin_size_in_binary | specifies the size of [.bin] code section if it was detected in this binary | 0 | 
 | .sxdata_size_in_binary | specifies the size of [.sxdata] code section if it was detected in this binary | 0 | 
 | .text1_size_in_binary | specifies the size of [.text1] code section if it was detected in this binary | 0 | 
 | .textbss_size_in_binary | specifies the size of [.textbss] code section if it was detected in this binary | 0 | 
 | .0lgfxz_size_in_binary | specifies the size of [.0lgfxz] code section if it was detected in this binary | 0 | 
 | .l2_size_in_binary | specifies the size of [.l2] code section if it was detected in this binary | 0 | 
 | .orpc_size_in_binary | specifies the size of [.orpc] code section if it was detected in this binary | 0 | 
 | .retplne_size_in_binary | specifies the size of [.retplne] code section if it was detected in this binary | 0 | 
 | .41hfa_size_in_binary | specifies the size of [.41hfa] code section if it was detected in this binary | 0 | 
 | .6ll_size_in_binary | specifies the size of [.6ll] code section if it was detected in this binary | 0 | 
 | .7ps_size_in_binary | specifies the size of [.7ps] code section if it was detected in this binary | 0 | 
 | .ap0x_size_in_binary | specifies the size of [.ap0x] code section if it was detected in this binary | 0 | 
 | .aspack_size_in_binary | specifies the size of [.aspack] code section if it was detected in this binary | 0 | 
 | .bedrock_size_in_binary | specifies the size of [.bedrock] code section if it was detected in this binary | 0 | 
 | .boot_size_in_binary | specifies the size of [.boot] code section if it was detected in this binary | 0 | 
 | .cfg_size_in_binary | specifies the size of [.cfg] code section if it was detected in this binary | 0 | 
 | .cwkw_size_in_binary | specifies the size of [.cwkw] code section if it was detected in this binary | 0 | 
 | .data3_size_in_binary | specifies the size of [.data3] code section if it was detected in this binary | 0 | 
 | .date1_size_in_binary | specifies the size of [.date1] code section if it was detected in this binary | 0 | 
 | .ddata_size_in_binary | specifies the size of [.ddata] code section if it was detected in this binary | 0 | 
 | .enigma1_size_in_binary | specifies the size of [.enigma1] code section if it was detected in this binary | 0 | 
 | .enigma2_size_in_binary | specifies the size of [.enigma2] code section if it was detected in this binary | 0 | 
 | .exports_size_in_binary | specifies the size of [.exports] code section if it was detected in this binary | 0 | 
 | .fleilpb_size_in_binary | specifies the size of [.fleilpb] code section if it was detected in this binary | 0 | 
 | .gegofon_size_in_binary | specifies the size of [.gegofon] code section if it was detected in this binary | 0 | 
 | .gufav_size_in_binary | specifies the size of [.gufav] code section if it was detected in this binary | 0 | 
 | .hidata_size_in_binary | specifies the size of [.hidata] code section if it was detected in this binary | 0 | 
 | .hky_size_in_binary | specifies the size of [.hky] code section if it was detected in this binary | 0 | 
 | .hs94nbl_size_in_binary | specifies the size of [.hs94nbl] code section if it was detected in this binary | 0 | 
 | .i2o_size_in_binary | specifies the size of [.i2o] code section if it was detected in this binary | 0 | 
 | .idata2_size_in_binary | specifies the size of [.idata2] code section if it was detected in this binary | 0 | 
 | .irdata_size_in_binary | specifies the size of [.irdata] code section if it was detected in this binary | 0 | 
 | .iwpd_size_in_binary | specifies the size of [.iwpd] code section if it was detected in this binary | 0 | 
 | .j_size_in_binary | specifies the size of [.j] code section if it was detected in this binary | 0 | 
 | .jiisysj_size_in_binary | specifies the size of [.jiisysj] code section if it was detected in this binary | 0 | 
 | .mpyess2_size_in_binary | specifies the size of [.mpyess2] code section if it was detected in this binary | 0 | 
 | .mysec10_size_in_binary | specifies the size of [.mysec10] code section if it was detected in this binary | 0 | 
 | .newiid_size_in_binary | specifies the size of [.newiid] code section if it was detected in this binary | 0 | 
 | .p59108_size_in_binary | specifies the size of [.p59108] code section if it was detected in this binary | 0 | 
 | .qqiolo_size_in_binary | specifies the size of [.qqiolo] code section if it was detected in this binary | 0 | 
 | .qwdfr0_size_in_binary | specifies the size of [.qwdfr0] code section if it was detected in this binary | 0 | 
 | .rda_size_in_binary | specifies the size of [.rda] code section if it was detected in this binary | 0 | 
 | .rdat_size_in_binary | specifies the size of [.rdat] code section if it was detected in this binary | 0 | 
 | .rrth0_size_in_binary | specifies the size of [.rrth0] code section if it was detected in this binary | 0 | 
 | .rrth1_size_in_binary | specifies the size of [.rrth1] code section if it was detected in this binary | 0 | 
 | .rrth2_size_in_binary | specifies the size of [.rrth2] code section if it was detected in this binary | 0 | 
 | .rubutiz_size_in_binary | specifies the size of [.rubutiz] code section if it was detected in this binary | 0 | 
 | .sbss_size_in_binary | specifies the size of [.sbss] code section if it was detected in this binary | 0 | 
 | .script_size_in_binary | specifies the size of [.script] code section if it was detected in this binary | 0 | 
 | .shared_size_in_binary | specifies the size of [.shared] code section if it was detected in this binary | 0 | 
 | .stub_size_in_binary | specifies the size of [.stub] code section if it was detected in this binary | 0 | 
 | .sw_size_in_binary | specifies the size of [.sw] code section if it was detected in this binary | 0 | 
 | .tdata0_size_in_binary | specifies the size of [.tdata0] code section if it was detected in this binary | 0 | 
 | .tdata1_size_in_binary | specifies the size of [.tdata1] code section if it was detected in this binary | 0 | 
 | .tdata2_size_in_binary | specifies the size of [.tdata2] code section if it was detected in this binary | 0 | 
 | .trace_size_in_binary | specifies the size of [.trace] code section if it was detected in this binary | 0 | 
 | .udata_size_in_binary | specifies the size of [.udata] code section if it was detected in this binary | 0 | 
 | .upx_size_in_binary | specifies the size of [.upx] code section if it was detected in this binary | 0 | 
 | .uzp0_size_in_binary | specifies the size of [.uzp0] code section if it was detected in this binary | 0 | 
 | .uzp1_size_in_binary | specifies the size of [.uzp1] code section if it was detected in this binary | 0 | 
 | .w_size_in_binary | specifies the size of [.w] code section if it was detected in this binary | 0 | 
 | .wap2il_size_in_binary | specifies the size of [.wap2il] code section if it was detected in this binary | 0 | 
 | .wdata_size_in_binary | specifies the size of [.wdata] code section if it was detected in this binary | 0 | 
 | .wn_size_in_binary | specifies the size of [.wn] code section if it was detected in this binary | 0 | 
 | .xaq_size_in_binary | specifies the size of [.xaq] code section if it was detected in this binary | 0 | 
 | .xml_size_in_binary | specifies the size of [.xml] code section if it was detected in this binary | 0 | 
 | .xu8i_size_in_binary | specifies the size of [.xu8i] code section if it was detected in this binary | 0 | 
 | .yj_size_in_binary | specifies the size of [.yj] code section if it was detected in this binary | 0 | 
 | .ywi1hpv_size_in_binary | specifies the size of [.ywi1hpv] code section if it was detected in this binary | 0 | 
 | references_domain | yara scan results identifying if the binary was flagged to contain references_domain | FALSE | 
 | references_ip | yara scan results identifying if the binary was flagged to contain references_ip | FALSE | 
 | references_url | yara scan results identifying if the binary was flagged to contain references_url | TRUE | 
 | inject_thread_capability | yara scan results identifying if the binary was flagged to contain inject_thread_capability | FALSE | 
 | create_process_capability | yara scan results identifying if the binary was flagged to contain create_process_capability | FALSE | 
 | persistence_capability | yara scan results identifying if the binary was flagged to contain persistence_capability | FALSE | 
 | hijack_network_capability | yara scan results identifying if the binary was flagged to contain hijack_network_capability | FALSE | 
 | create_service_capability | yara scan results identifying if the binary was flagged to contain create_service_capability | FALSE | 
 | create_com_service_capability | yara scan results identifying if the binary was flagged to contain create_com_service_capability | FALSE | 
 | network_udp_sock_capability | yara scan results identifying if the binary was flagged to contain network_udp_sock_capability | FALSE | 
 | network_tcp_listen_capability | yara scan results identifying if the binary was flagged to contain network_tcp_listen_capability | FALSE | 
 | network_dyndns_capability | yara scan results identifying if the binary was flagged to contain network_dyndns_capability | FALSE | 
 | network_toredo_capability | yara scan results identifying if the binary was flagged to contain network_toredo_capability | FALSE | 
 | network_smtp_dotnet_capability | yara scan results identifying if the binary was flagged to contain network_smtp_dotnet_capability | FALSE | 
 | network_smtp_raw_capability | yara scan results identifying if the binary was flagged to contain network_smtp_raw_capability | FALSE | 
 | network_smtp_vb_capability | yara scan results identifying if the binary was flagged to contain network_smtp_vb_capability | FALSE | 
 | network_p2p_win_capability | yara scan results identifying if the binary was flagged to contain network_p2p_win_capability | FALSE | 
 | network_tor_capability | yara scan results identifying if the binary was flagged to contain network_tor_capability | FALSE | 
 | network_irc_capability | yara scan results identifying if the binary was flagged to contain network_irc_capability | FALSE | 
 | network_http_capability | yara scan results identifying if the binary was flagged to contain network_http_capability | FALSE | 
 | network_dropper_capability | yara scan results identifying if the binary was flagged to contain network_dropper_capability | FALSE | 
 | network_ftp_capability | yara scan results identifying if the binary was flagged to contain network_ftp_capability | FALSE | 
 | network_tcp_socket_capability | yara scan results identifying if the binary was flagged to contain network_tcp_socket_capability | FALSE | 
 | network_dns_capability | yara scan results identifying if the binary was flagged to contain network_dns_capability | FALSE | 
 | network_ssl_capability | yara scan results identifying if the binary was flagged to contain network_ssl_capability | FALSE | 
 | network_dga_capability | yara scan results identifying if the binary was flagged to contain network_dga_capability | FALSE | 
 | bitcoin_capability | yara scan results identifying if the binary was flagged to contain bitcoin_capability | FALSE | 
 | interact_with_security_certificate_capability | yara scan results identifying if the binary was flagged to contain interact_with_security_certificate_capability | FALSE | 
 | escalate_privilege_capability | yara scan results identifying if the binary was flagged to contain escalate_privilege_capability | FALSE | 
 | take_screenshot_capability | yara scan results identifying if the binary was flagged to contain take_screenshot_capability | FALSE | 
 | look_up_ip_capability | yara scan results identifying if the binary was flagged to contain look_up_ip_capability | FALSE | 
 | dyndns_capability | yara scan results identifying if the binary was flagged to contain dyndns_capability | FALSE | 
 | look_up_geo_capability | yara scan results identifying if the binary was flagged to contain look_up_geo_capability | FALSE | 
 | keylogger_capability | yara scan results identifying if the binary was flagged to contain keylogger_capability | FALSE | 
 | reveal_local_credentials_capability | yara scan results identifying if the binary was flagged to contain reveal_local_credentials_capability | FALSE | 
 | sniff_audio_capability | yara scan results identifying if the binary was flagged to contain sniff_audio_capability | FALSE | 
 | cred_ff_capability | yara scan results identifying if the binary was flagged to contain cred_ff_capability | FALSE | 
 | cred_vnc_capability | yara scan results identifying if the binary was flagged to contain cred_vnc_capability | FALSE | 
 | cred_ie7 | yara scan results identifying if the binary was flagged to contain cred_ie7 | FALSE | 
 | sniff_lan | yara scan results identifying if the binary was flagged to contain sniff_lan | FALSE | 
 | migrate_apc | yara scan results identifying if the binary was flagged to contain migrate_apc | FALSE | 
 | spreading_file | yara scan results identifying if the binary was flagged to contain spreading_file | FALSE | 
 | spreading_share | yara scan results identifying if the binary was flagged to contain spreading_share | FALSE | 
 | rat_vnc | yara scan results identifying if the binary was flagged to contain rat_vnc | FALSE | 
 | rat_rdp | yara scan results identifying if the binary was flagged to contain rat_rdp | FALSE | 
 | rat_telnet | yara scan results identifying if the binary was flagged to contain rat_telnet | FALSE | 
 | rat_webcam | yara scan results identifying if the binary was flagged to contain rat_webcam | FALSE | 
 | win_mutex | yara scan results identifying if the binary was flagged to contain win_mutex | FALSE | 
 | win_registry | yara scan results identifying if the binary was flagged to contain win_registry | FALSE | 
 | win_token | yara scan results identifying if the binary was flagged to contain win_token | FALSE | 
 | win_private_profile | yara scan results identifying if the binary was flagged to contain win_private_profile | FALSE | 
 | win_files_operation | yara scan results identifying if the binary was flagged to contain win_files_operation | FALSE | 
 | str_win32_winsock2_library | yara scan results identifying if the binary was flagged to contain str_win32_winsock2_library | FALSE | 
 | str_win32_wininet_library | yara scan results identifying if the binary was flagged to contain str_win32_wininet_library | FALSE | 
 | str_win32_internet_api | yara scan results identifying if the binary was flagged to contain str_win32_internet_api | FALSE | 
 | str_win32_http_api | yara scan results identifying if the binary was flagged to contain str_win32_http_api | FALSE | 
 | ldpreload | yara scan results identifying if the binary was flagged to contain ldpreload | FALSE | 
 | mysql_database_presence | yara scan results identifying if the binary was flagged to contain mysql_database_presence | FALSE | 
 | maldoc_ole_file_magic_number | yara scan results identifying if the binary was flagged to contain maldoc_ole_file_magic_number | FALSE | 
 | maldoc | yara scan results identifying if the binary was flagged to contain maldoc | FALSE | 
 | system_tools | yara scan results identifying if the binary was flagged to contain system_tools | FALSE | 
 | browsers | yara scan results identifying if the binary was flagged to contain browsers | FALSE | 
 | re_tools | yara scan results identifying if the binary was flagged to contain re_tools | FALSE | 
 | antivirus | yara scan results identifying if the binary was flagged to contain antivirus | FALSE | 
 | antivm | yara scan results identifying if the binary was flagged to contain antivm | FALSE | 
 | vm_generic_detection | yara scan results identifying if the binary was flagged to contain vm_generic_detection | FALSE | 
 | vmware_detection | yara scan results identifying if the binary was flagged to contain vmware_detection | FALSE | 
 | sandboxie_detection | yara scan results identifying if the binary was flagged to contain sandboxie_detection | FALSE | 
 | virtualpc_detection | yara scan results identifying if the binary was flagged to contain virtualpc_detection | FALSE | 
 | virtualbox_detection | yara scan results identifying if the binary was flagged to contain virtualbox_detection | FALSE | 
 | parallels_detection | yara scan results identifying if the binary was flagged to contain parallels_detection | FALSE | 
 | qemu_detection | yara scan results identifying if the binary was flagged to contain qemu_detection | FALSE | 
 | dropper_strings | yara scan results identifying if the binary was flagged to contain dropper_strings | FALSE | 
 | autoit_compiled_script | yara scan results identifying if the binary was flagged to contain autoit_compiled_script | FALSE | 
 | wmi_strings | yara scan results identifying if the binary was flagged to contain wmi_strings | FALSE | 
 | obfuscated_strings | yara scan results identifying if the binary was flagged to contain obfuscated_strings | FALSE | 
 | base64d_pe | yara scan results identifying if the binary was flagged to contain base64d_pe | FALSE | 
 | misc_suspicious_strings | yara scan results identifying if the binary was flagged to contain misc_suspicious_strings | FALSE | 
 | bits_clsid | yara scan results identifying if the binary was flagged to contain bits_clsid | FALSE | 
 | hexencodedtextpe | yara scan results identifying if the binary was flagged to contain hexencodedtextpe | FALSE | 








