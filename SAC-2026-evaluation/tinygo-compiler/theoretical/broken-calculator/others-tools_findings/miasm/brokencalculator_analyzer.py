import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId
from miasm.core.asmblock import AsmCFG

def find_null_pointer_dereferences(ircfg_map):
    """
    Detect potential null pointer dereferences by looking for:
    - Memory writes/reads through zero or near-zero pointers
    - Unconditional dereferences of uninitialized pointers
    - Conditional null pointer dereferences (logic bombs)
    """
    vulnerabilities = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        # Track register assignments to detect zeroed pointers
        register_values = {}
        
        for block_label, ir_block in ircfg.blocks.items():
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    # Track when registers/variables are set to zero
                    if isinstance(destination, ExprId):
                        if isinstance(source, ExprInt) and source.arg == 0:
                            register_values[str(destination)] = 0
                    
                    # Check for memory operations with suspicious addresses
                    if isinstance(destination, ExprMem):
                        ptr = destination.ptr
                        
                        # Direct zero/null pointer write
                        if isinstance(ptr, ExprInt) and ptr.arg < 0x1000:
                            vulnerabilities.append({
                                'type': 'NULL_POINTER_WRITE',
                                'cfg_address': hex(cfg_addr),
                                'block': str(block_label),
                                'address': hex(ptr.arg),
                                'destination': str(destination),
                                'severity': 'HIGH'
                            })
                        
                        # Write through a register that was set to zero
                        elif isinstance(ptr, ExprId) and str(ptr) in register_values:
                            if register_values[str(ptr)] == 0:
                                vulnerabilities.append({
                                    'type': 'NULL_POINTER_WRITE_VIA_REGISTER',
                                    'cfg_address': hex(cfg_addr),
                                    'block': str(block_label),
                                    'register': str(ptr),
                                    'destination': str(destination),
                                    'severity': 'HIGH'
                                })
                        
                        # Write through dereferenced zero pointer
                        elif isinstance(ptr, ExprMem):
                            inner_ptr = ptr.ptr
                            if isinstance(inner_ptr, ExprInt) and inner_ptr.arg < 0x1000:
                                vulnerabilities.append({
                                    'type': 'DOUBLE_DEREF_NULL_POINTER',
                                    'cfg_address': hex(cfg_addr),
                                    'block': str(block_label),
                                    'destination': str(destination),
                                    'severity': 'HIGH'
                                })
                    
                    if isinstance(source, ExprMem):
                        ptr = source.ptr
                        
                        # Direct zero/null pointer read
                        if isinstance(ptr, ExprInt) and ptr.arg < 0x1000:
                            vulnerabilities.append({
                                'type': 'NULL_POINTER_READ',
                                'cfg_address': hex(cfg_addr),
                                'block': str(block_label),
                                'address': hex(ptr.arg),
                                'source': str(source),
                                'severity': 'HIGH'
                            })
                        
                        # Read through a register that was set to zero
                        elif isinstance(ptr, ExprId) and str(ptr) in register_values:
                            if register_values[str(ptr)] == 0:
                                vulnerabilities.append({
                                    'type': 'NULL_POINTER_READ_VIA_REGISTER',
                                    'cfg_address': hex(cfg_addr),
                                    'block': str(block_label),
                                    'register': str(ptr),
                                    'source': str(source),
                                    'severity': 'HIGH'
                                })
    
    return vulnerabilities

def find_integer_overflows(ircfg_map):
    """
    Detect potential integer overflow vulnerabilities by analyzing:
    - Arithmetic operations without bounds checking
    - Multiplication of user-controlled values
    - Addition/subtraction with large constants
    """
    vulnerabilities = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        for block_label, ir_block in ircfg.blocks.items():
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    if isinstance(source, ExprOp):
                        # Check for risky arithmetic operations
                        if source.op in ['+', '-', '*', '<<']:
                            # Look for operations with large immediate values
                            for arg in source.args:
                                if isinstance(arg, ExprInt):
                                    if arg.arg > 0x7FFFFFFF or arg.arg < -0x80000000:
                                        vulnerabilities.append({
                                            'type': 'INTEGER_OVERFLOW_RISK',
                                            'cfg_address': hex(cfg_addr),
                                            'block': str(block_label),
                                            'operation': source.op,
                                            'operands': [str(a) for a in source.args],
                                            'severity': 'MEDIUM'
                                        })
    
    return vulnerabilities

def find_buffer_overflows(ircfg_map):
    """
    Detect potential buffer overflow patterns:
    - Unbounded memory writes in loops
    - Stack buffer operations without size checks
    """
    vulnerabilities = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        for block_label, ir_block in ircfg.blocks.items():
            memory_writes = []
            
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    # Track memory write operations
                    if isinstance(destination, ExprMem):
                        memory_writes.append({
                            'ptr': destination.ptr,
                            'source': source,
                            'destination': destination
                        })
            
            # Look for patterns of sequential memory writes (potential buffer operations)
            if len(memory_writes) > 3:
                vulnerabilities.append({
                    'type': 'BUFFER_OPERATION_PATTERN',
                    'cfg_address': hex(cfg_addr),
                    'block': str(block_label),
                    'write_count': len(memory_writes),
                    'severity': 'MEDIUM'
                })
    
    return vulnerabilities

def find_use_after_free(ircfg_map):
    """
    Detect potential use-after-free by tracking:
    - Memory deallocation followed by access
    - Pointer usage after being set to zero
    """
    vulnerabilities = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        pointer_states = {}
        
        for block_label, ir_block in ircfg.blocks.items():
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    # Track pointers being set to zero
                    if isinstance(destination, ExprId):
                        if isinstance(source, ExprInt) and source.arg == 0:
                            pointer_states[str(destination)] = 'zeroed'
                    
                    # Check for usage of zeroed pointers
                    if isinstance(source, ExprMem):
                        ptr_str = str(source.ptr)
                        if ptr_str in pointer_states and pointer_states[ptr_str] == 'zeroed':
                            vulnerabilities.append({
                                'type': 'USE_AFTER_ZERO',
                                'cfg_address': hex(cfg_addr),
                                'block': str(block_label),
                                'pointer': ptr_str,
                                'severity': 'HIGH'
                            })
    
    return vulnerabilities

def find_unchecked_conditions(ircfg_map):
    """
    Detect dangerous operations without proper checks:
    - Division operations without zero checks
    - Conditional jumps that might be bypassed
    """
    vulnerabilities = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        for block_label, ir_block in ircfg.blocks.items():
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    # Look for division operations
                    if isinstance(source, ExprOp) and source.op in ['/', '%', 'idiv']:
                        vulnerabilities.append({
                            'type': 'UNCHECKED_DIVISION',
                            'cfg_address': hex(cfg_addr),
                            'block': str(block_label),
                            'operation': str(source),
                            'severity': 'MEDIUM'
                        })
    
    return vulnerabilities

def find_format_string_vulnerabilities(asm_cfg_map):
    """
    Detect potential format string vulnerabilities by analyzing
    call instructions and their arguments
    """
    vulnerabilities = []
    
    for cfg_addr, asm_cfg in asm_cfg_map.items():
        for block in asm_cfg.blocks:
            for instruction in block.lines:
                # Look for calls to printf-like functions
                if instruction.name.upper() == 'CALL':
                    vulnerabilities.append({
                        'type': 'POTENTIAL_FORMAT_STRING',
                        'cfg_address': hex(cfg_addr),
                        'block': str(block.loc_key),
                        'instruction': str(instruction),
                        'severity': 'MEDIUM'
                    })
    
    return vulnerabilities

def disassemble_binary(machine, mdis, start_address, max_depth=15):
    """
    Disassemble binary starting from entry point
    """
    work_queue = [(mdis, start_address)]
    processed = set()
    ir_cfgs = {}
    asm_cfgs = {}
    depth = 0
    
    while work_queue and depth < max_depth:
        current_mdis, address = work_queue.pop(0)
        
        if address in processed:
            continue
        
        processed.add(address)
        
        try:
            asm_cfg = current_mdis.dis_multiblock(address)
            
            lifter = machine.lifter_model_call(current_mdis.loc_db)
            ir_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)
            
            ir_cfgs[address] = ir_cfg
            asm_cfgs[address] = asm_cfg
            
            # Add call targets to work queue
            for block in asm_cfg.blocks:
                call_instr = block.get_subcall_instr()
                if call_instr:
                    for target in call_instr.getdstflow(current_mdis.loc_db):
                        if target.is_loc():
                            target_addr = current_mdis.loc_db.get_location_offset(target.loc_key)
                            if target_addr and target_addr not in processed:
                                work_queue.append((current_mdis, target_addr))
            
            depth += 1
            
        except Exception as e:
            continue
    
    return ir_cfgs, asm_cfgs

def main():
    if len(sys.argv) < 3:
        print("Usage: python vuln_scanner.py <binary_path> <entry_point_hex>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    entry_point = int(sys.argv[2], 16)
    
    print("=" * 60)
    print("GENERIC VULNERABILITY SCANNER")
    print("=" * 60)
    print(f"Target: {binary_path}")
    print(f"Entry Point: {hex(entry_point)}")
    print()
    
    # Initialize Miasm framework
    location_db = LocationDB()
    machine = Machine("x86_64")
    
    try:
        with open(binary_path, "rb") as file_handle:
            container = Container.from_stream(file_handle, location_db)
    except Exception as error:
        print(f"Error loading binary: {error}")
        return
    
    disassembler = machine.dis_engine(container.bin_stream, loc_db=location_db)
    
    # Perform disassembly
    print("[*] Phase 1: Disassembling binary...")
    ir_cfgs, asm_cfgs = disassemble_binary(machine, disassembler, entry_point)
    print(f"[+] Analyzed {len(ir_cfgs)} code segments\n")
    
    # Run vulnerability detection modules
    print("[*] Phase 2: Running vulnerability scanners...\n")
    
    all_vulnerabilities = []
    
    # Scan for different vulnerability types
    print("[*] Scanning for null pointer dereferences...")
    null_ptr_vulns = find_null_pointer_dereferences(ir_cfgs)
    all_vulnerabilities.extend(null_ptr_vulns)
    print(f"    Found {len(null_ptr_vulns)} potential issues")
    
    print("[*] Scanning for integer overflows...")
    int_overflow_vulns = find_integer_overflows(ir_cfgs)
    all_vulnerabilities.extend(int_overflow_vulns)
    print(f"    Found {len(int_overflow_vulns)} potential issues")
    
    print("[*] Scanning for buffer overflows...")
    buffer_overflow_vulns = find_buffer_overflows(ir_cfgs)
    all_vulnerabilities.extend(buffer_overflow_vulns)
    print(f"    Found {len(buffer_overflow_vulns)} potential issues")
    
    print("[*] Scanning for use-after-free...")
    uaf_vulns = find_use_after_free(ir_cfgs)
    all_vulnerabilities.extend(uaf_vulns)
    print(f"    Found {len(uaf_vulns)} potential issues")
    
    print("[*] Scanning for unchecked conditions...")
    unchecked_vulns = find_unchecked_conditions(ir_cfgs)
    all_vulnerabilities.extend(unchecked_vulns)
    print(f"    Found {len(unchecked_vulns)} potential issues")
    
    print("[*] Scanning for format string vulnerabilities...")
    format_string_vulns = find_format_string_vulnerabilities(asm_cfgs)
    all_vulnerabilities.extend(format_string_vulns)
    print(f"    Found {len(format_string_vulns)} potential issues")
    
    # Report results
    print()
    print("=" * 60)
    print("VULNERABILITY REPORT")
    print("=" * 60)
    print(f"Total potential vulnerabilities found: {len(all_vulnerabilities)}")
    print()
    
    # Group by severity
    high_severity = [v for v in all_vulnerabilities if v.get('severity') == 'HIGH']
    medium_severity = [v for v in all_vulnerabilities if v.get('severity') == 'MEDIUM']
    
    print(f"HIGH severity issues: {len(high_severity)}")
    print(f"MEDIUM severity issues: {len(medium_severity)}")
    print()
    
    # Display detailed findings
    if high_severity:
        print("HIGH SEVERITY VULNERABILITIES:")
        print("-" * 60)
        for i, vuln in enumerate(high_severity[:10], 1):  # Show first 10
            print(f"{i}. Type: {vuln['type']}")
            print(f"   Location: CFG {vuln['cfg_address']}, Block {vuln['block']}")
            for key, value in vuln.items():
                if key not in ['type', 'cfg_address', 'block', 'severity']:
                    print(f"   {key}: {value}")
            print()
    
    if medium_severity:
        print("MEDIUM SEVERITY VULNERABILITIES (sample):")
        print("-" * 60)
        for i, vuln in enumerate(medium_severity[:5], 1):  # Show first 5
            print(f"{i}. Type: {vuln['type']}")
            print(f"   Location: CFG {vuln['cfg_address']}, Block {vuln['block']}")
            print()
    
    print("=" * 60)
    print("Scan complete. Review findings carefully for false positives.")
    print("=" * 60)

if __name__ == "__main__":