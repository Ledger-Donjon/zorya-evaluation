import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId
from miasm.core.asmblock import AsmCFG
from miasm.ir.ir import IRCFG
from future.utils import viewvalues

# Binary path and entry point - update these for your shift binary
binary_path = "./../../invalid-shift"
main_address = 0x000000000022afe0

def detect_bounds_check_patterns(ircfg_map):
    """
    Detect potential bounds checking operations and array access patterns
    """
    bounds_checks = []
    array_accesses = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    # Look for comparison operations (potential bounds checks)
                    if isinstance(src, ExprOp) and src.op in ['<', '>', '<=', '>=', '==', '!=', 'CMP']:
                        operands = []
                        for arg in src.args:
                            if isinstance(arg, ExprInt):
                                operands.append(('immediate', arg.arg))
                            elif isinstance(arg, ExprId):
                                operands.append(('register', str(arg)))
                            else:
                                operands.append(('expression', str(arg)))
                        
                        # Look for comparisons with small integers (potential array bounds)
                        has_small_constant = any(
                            op_type == 'immediate' and 0 < op_value < 1024 
                            for op_type, op_value in operands
                        )
                        
                        if has_small_constant:
                            bounds_checks.append({
                                'type': 'bounds_comparison',
                                'operation': src.op,
                                'operands': operands,
                                'block': lbl,
                                'instruction': assignblk,
                                'cfg_addr': addr
                            })
                    
                    # Look for memory access patterns that could be array accesses
                    elif isinstance(dst, ExprMem) or isinstance(src, ExprMem):
                        mem_expr = dst if isinstance(dst, ExprMem) else src
                        
                        # Check if memory address involves arithmetic (base + offset pattern)
                        if isinstance(mem_expr.ptr, ExprOp) and mem_expr.ptr.op in ['+', '-', '*']:
                            array_accesses.append({
                                'type': 'memory_access',
                                'address_expr': str(mem_expr.ptr),
                                'block': lbl,
                                'instruction': assignblk,
                                'cfg_addr': addr
                            })
    
    return bounds_checks, array_accesses

def find_panic_calls(ircfg_map, asm_cfg_map):
    """
    Look for calls to panic functions or runtime bounds check failures
    """
    panic_calls = []
    
    for addr, asmcfg in asm_cfg_map.items():
        for block in asmcfg.blocks:
            for instr in block.lines:
                instr_str = str(instr).lower()
                
                # Look for calls that might be panic/bounds check related
                if ('call' in instr_str and 
                    ('panic' in instr_str or 
                     'bounds' in instr_str or 
                     'slice' in instr_str or
                     'runtime' in instr_str)):
                    
                    panic_calls.append({
                        'type': 'panic_call',
                        'instruction': str(instr),
                        'block_addr': addr,
                        'block': block
                    })
    
    return panic_calls

def analyze_index_operations(ircfg_map):
    """
    Look for operations that extract indices from strings or arrays
    """
    index_operations = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    # Look for memory reads that could be string/array indexing
                    if isinstance(src, ExprMem):
                        # Pattern: register = memory[base + offset]
                        if isinstance(src.ptr, ExprOp) and src.ptr.op == '+':
                            index_operations.append({
                                'type': 'indexed_read',
                                'destination': str(dst),
                                'address_expr': str(src.ptr),
                                'block': lbl,
                                'instruction': assignblk,
                                'cfg_addr': addr
                            })
                    
                    # Look for register assignments that might be loading indices
                    elif isinstance(dst, ExprId) and isinstance(src, ExprMem):
                        index_operations.append({
                            'type': 'index_load',
                            'register': str(dst),
                            'source': str(src),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
    
    return index_operations

def correlate_oob_vulnerabilities(bounds_checks, array_accesses, panic_calls, index_operations):
    """
    Correlate bounds checks with array accesses to find potential OOB vulnerabilities
    """
    vulnerabilities = []
    
    # Group by CFG address to find related operations
    cfg_groups = {}
    
    for check in bounds_checks:
        cfg_addr = check['cfg_addr']
        if cfg_addr not in cfg_groups:
            cfg_groups[cfg_addr] = {'bounds_checks': [], 'array_accesses': [], 'panic_calls': [], 'index_ops': []}
        cfg_groups[cfg_addr]['bounds_checks'].append(check)
    
    for access in array_accesses:
        cfg_addr = access['cfg_addr']
        if cfg_addr not in cfg_groups:
            cfg_groups[cfg_addr] = {'bounds_checks': [], 'array_accesses': [], 'panic_calls': [], 'index_ops': []}
        cfg_groups[cfg_addr]['array_accesses'].append(access)
    
    for panic in panic_calls:
        # Panic calls don't have cfg_addr, so we'll associate them separately
        pass
    
    for index_op in index_operations:
        cfg_addr = index_op['cfg_addr']
        if cfg_addr not in cfg_groups:
            cfg_groups[cfg_addr] = {'bounds_checks': [], 'array_accesses': [], 'panic_calls': [], 'index_ops': []}
        cfg_groups[cfg_addr]['index_ops'].append(index_op)
    
    # Analyze each CFG group
    for cfg_addr, group in cfg_groups.items():
        if group['bounds_checks'] and group['array_accesses']:
            # Found both bounds checks and array accesses in same CFG
            vulnerabilities.append({
                'type': 'potential_oob',
                'cfg_addr': cfg_addr,
                'bounds_checks': group['bounds_checks'],
                'array_accesses': group['array_accesses'],
                'index_operations': group['index_ops'],
                'severity': 'HIGH'
            })
        elif group['bounds_checks']:
            # Found bounds checks without clear array access
            vulnerabilities.append({
                'type': 'bounds_check_only',
                'cfg_addr': cfg_addr,
                'bounds_checks': group['bounds_checks'],
                'severity': 'MEDIUM'
            })
        elif group['array_accesses']:
            # Found array accesses without clear bounds check
            vulnerabilities.append({
                'type': 'unchecked_access',
                'cfg_addr': cfg_addr,
                'array_accesses': group['array_accesses'],
                'severity': 'MEDIUM'
            })
    
    # Add panic calls as separate high-priority findings
    for panic in panic_calls:
        vulnerabilities.append({
            'type': 'panic_call_found',
            'panic_info': panic,
            'severity': 'HIGH'
        })
    
    return vulnerabilities

def disassemble_and_analyze(machine, mdis, start_addr, follow_calls=True):
    """
    Disassemble and analyze for out-of-bounds vulnerabilities
    """
    todo = [(mdis, start_addr)]
    done = set()
    ircfg_map = {}
    asm_cfg_map = {}
    
    print(f"Starting OOB analysis from: {hex(start_addr)}")
    
    while todo:
        mdis, addr = todo.pop(0)
        if addr in done:
            continue
        done.add(addr)
        
        try:
            asmcfg = mdis.dis_multiblock(addr)
            print(f"Analyzing block at {hex(addr)}: {len(asmcfg.blocks)} basic blocks")
            
            lifter = machine.lifter_model_call(mdis.loc_db)
            ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
            ircfg_map[addr] = ircfg
            asm_cfg_map[addr] = asmcfg
            
            # Follow function calls
            if follow_calls:
                for block in asmcfg.blocks:
                    instr = block.get_subcall_instr()
                    if instr:
                        for dest in instr.getdstflow(mdis.loc_db):
                            if dest.is_loc():
                                offset = mdis.loc_db.get_location_offset(dest.loc_key)
                                if offset and offset not in done:
                                    todo.append((mdis, offset))
                                    
        except Exception as e:
            print(f"Error analyzing {hex(addr)}: {e}")
            continue
    
    return ircfg_map, asm_cfg_map

def main():
    if len(sys.argv) > 1:
        global binary_path, main_address
        binary_path = sys.argv[1]
        if len(sys.argv) > 2:
            main_address = int(sys.argv[2], 16)
    
    print("=== MIASM Out-of-Bounds Vulnerability Discovery ===")
    print(f"Target: {binary_path}")
    print(f"Entry point: {hex(main_address)}")
    
    # Initialize MIASM
    loc_db = LocationDB()
    machine = Machine("x86_64")
    
    try:
        with open(binary_path, "rb") as f:
            container = Container.from_stream(f, loc_db)
        print("SUCCESS: Binary loaded successfully")
    except Exception as e:
        print(f"ERROR: Failed to load binary: {e}")
        return
    
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    
    # Perform analysis
    print("\n=== Phase 1: Disassembly and IR Generation ===")
    ircfg_map, asm_cfg_map = disassemble_and_analyze(machine, mdis, main_address)
    
    if not ircfg_map:
        print("ERROR: No analyzable code found")
        return
    
    print(f"SUCCESS: Analyzed {len(ircfg_map)} code segments")
    
    # Phase 2: Bounds checking analysis
    print("\n=== Phase 2: Bounds Check Pattern Detection ===")
    bounds_checks, array_accesses = detect_bounds_check_patterns(ircfg_map)
    
    print(f"Found {len(bounds_checks)} potential bounds check operations")
    print(f"Found {len(array_accesses)} array access patterns")
    
    # Phase 3: Panic call detection
    print("\n=== Phase 3: Panic Call Detection ===")
    panic_calls = find_panic_calls(ircfg_map, asm_cfg_map)
    
    print(f"Found {len(panic_calls)} potential panic/runtime calls")
    
    # Phase 4: Index operation analysis
    print("\n=== Phase 4: Index Operation Analysis ===")
    index_operations = analyze_index_operations(ircfg_map)
    
    print(f"Found {len(index_operations)} index-related operations")
    
    # Phase 5: Vulnerability correlation
    print("\n=== Phase 5: Out-of-Bounds Vulnerability Analysis ===")
    vulnerabilities = correlate_oob_vulnerabilities(bounds_checks, array_accesses, panic_calls, index_operations)
    
    print(f"\nOUT-OF-BOUNDS VULNERABILITY REPORT:")
    print(f"Found {len(vulnerabilities)} potential OOB vulnerabilities")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n--- OOB Vulnerability #{i} ---")
        print(f"Type: {vuln['type']}")
        print(f"Severity: {vuln['severity']}")
        
        if 'cfg_addr' in vuln:
            print(f"Location: CFG at {hex(vuln['cfg_addr'])}")
        
        if 'bounds_checks' in vuln:
            print(f"Bounds checks found:")
            for check in vuln['bounds_checks'][:3]:  # Show first 3
                print(f"  - {check['operation']} with operands: {check['operands']}")
        
        if 'array_accesses' in vuln:
            print(f"Array accesses found:")
            for access in vuln['array_accesses'][:3]:  # Show first 3
                print(f"  - Memory access: {access['address_expr']}")
        
        if 'index_operations' in vuln:
            print(f"Index operations found:")
            for idx_op in vuln['index_operations'][:3]:  # Show first 3
                print(f"  - {idx_op['type']}: {idx_op.get('address_expr', idx_op.get('source', 'N/A'))}")
        
        if 'panic_info' in vuln:
            print(f"Panic call: {vuln['panic_info']['instruction']}")
    
    # Generate output files
    try:
        full_cfg = AsmCFG(mdis.loc_db)
        for blocks in viewvalues(asm_cfg_map):
            full_cfg += blocks
        
        with open('oob_analysis.dot', 'w') as f:
            f.write(full_cfg.dot(offset=True))
        print(f"\nSUCCESS: Control flow graph saved to oob_analysis.dot")
    except Exception as e:
        print(f"ERROR: Could not generate CFG: {e}")
    
    print(f"\n=== Analysis Complete ===")
    if vulnerabilities:
        print("ALERT: POTENTIAL OUT-OF-BOUNDS VULNERABILITIES DETECTED")
        print("Look for:")
        print("- Bounds checks with small constants (array sizes like 64)")
        print("- Index operations reading from strings (s[0] patterns)")
        print("- Memory accesses following comparisons")
    else:
        print("INFO: No obvious OOB vulnerabilities found in static analysis")

if __name__ == "__main__":
    main()
