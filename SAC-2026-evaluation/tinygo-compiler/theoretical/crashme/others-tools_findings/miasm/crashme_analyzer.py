import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId
from miasm.core.asmblock import AsmCFG
from miasm.ir.ir import IRCFG
from future.utils import viewvalues

# Binary path and entry point
binary_path = "target_binary"
main_address = 0x400000

def analyze_memory_operations(ircfg_map):
    """
    Analyze all memory operations for potential vulnerabilities
    """
    memory_ops = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    # Memory writes
                    if isinstance(dst, ExprMem):
                        memory_ops.append({
                            'type': 'memory_write',
                            'address': str(dst.ptr),
                            'value': str(src),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
                    
                    # Memory reads
                    elif isinstance(src, ExprMem):
                        memory_ops.append({
                            'type': 'memory_read',
                            'address': str(src.ptr),
                            'destination': str(dst),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
    
    return memory_ops

def analyze_arithmetic_operations(ircfg_map):
    """
    Analyze arithmetic operations that could lead to vulnerabilities
    """
    arithmetic_ops = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    if isinstance(src, ExprOp):
                        arithmetic_ops.append({
                            'operation': src.op,
                            'operands': [str(arg) for arg in src.args],
                            'result': str(dst),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
    
    return arithmetic_ops

def analyze_comparisons(ircfg_map):
    """
    Analyze all comparison operations
    """
    comparisons = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    # Direct comparisons
                    if isinstance(src, ExprOp) and src.op in ['==', '!=', '<', '>', '<=', '>=', 'CMP']:
                        operands = []
                        for arg in src.args:
                            if isinstance(arg, ExprInt):
                                operands.append(('constant', arg.arg))
                            elif isinstance(arg, ExprId):
                                operands.append(('register', str(arg)))
                            else:
                                operands.append(('expression', str(arg)))
                        
                        comparisons.append({
                            'operation': src.op,
                            'operands': operands,
                            'result': str(dst),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
                    
                    # Conditional expressions
                    elif isinstance(src, ExprCond):
                        comparisons.append({
                            'operation': 'conditional',
                            'condition': str(src.cond),
                            'true_expr': str(src.src1),
                            'false_expr': str(src.src2),
                            'result': str(dst),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
    
    return comparisons

def analyze_function_calls(asm_cfg_map):
    """
    Analyze function calls and their targets
    """
    function_calls = []
    
    for addr, asmcfg in asm_cfg_map.items():
        for block in asmcfg.blocks:
            for instr in block.lines:
                instr_str = str(instr).lower()
                
                if 'call' in instr_str:
                    function_calls.append({
                        'instruction': str(instr),
                        'caller_addr': addr,
                        'block_addr': block.loc_key,
                    })
    
    return function_calls

def detect_dangerous_patterns(memory_ops, arithmetic_ops, comparisons, function_calls):
    """
    Detect potentially dangerous patterns from the analysis results
    """
    vulnerabilities = []
    
    # Pattern 1: Memory writes to low addresses
    for mem_op in memory_ops:
        if mem_op['type'] == 'memory_write':
            addr_str = mem_op['address']
            if addr_str.isdigit() and int(addr_str) < 0x1000:
                vulnerabilities.append({
                    'type': 'low_memory_write',
                    'severity': 'HIGH' if int(addr_str) == 0 else 'MEDIUM',
                    'details': mem_op
                })
    
    # Pattern 2: Arithmetic operations that could overflow
    for arith_op in arithmetic_ops:
        if arith_op['operation'] in ['+', '-', '*']:
            vulnerabilities.append({
                'type': 'arithmetic_operation',
                'severity': 'LOW',
                'details': arith_op
            })
    
    # Pattern 3: Comparisons with interesting constants
    for comp in comparisons:
        if 'operands' in comp:
            for op_type, op_value in comp['operands']:
                if op_type == 'constant':
                    vulnerabilities.append({
                        'type': 'comparison_with_constant',
                        'severity': 'INFO',
                        'constant_value': op_value,
                        'details': comp
                    })
    
    # Pattern 4: Function calls that might be dangerous
    for call in function_calls:
        call_str = call['instruction'].lower()
        if any(keyword in call_str for keyword in ['panic', 'abort', 'exit', 'runtime']):
            vulnerabilities.append({
                'type': 'dangerous_function_call',
                'severity': 'MEDIUM',
                'details': call
            })
    
    return vulnerabilities

def disassemble_and_analyze(machine, mdis, start_addr, follow_calls=True):
    """
    Generic disassembly and analysis
    """
    todo = [(mdis, start_addr)]
    done = set()
    ircfg_map = {}
    asm_cfg_map = {}
    
    print(f"Starting analysis from: {hex(start_addr)}")
    
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
    
    print("=== Generic MIASM Vulnerability Scanner ===")
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
    print("\n=== Phase 1: Disassembly ===")
    ircfg_map, asm_cfg_map = disassemble_and_analyze(machine, mdis, main_address)
    
    if not ircfg_map:
        print("ERROR: No analyzable code found")
        return
    
    print(f"SUCCESS: Analyzed {len(ircfg_map)} code segments")
    
    # Phase 2: Memory operations
    print("\n=== Phase 2: Memory Operations Analysis ===")
    memory_ops = analyze_memory_operations(ircfg_map)
    print(f"Found {len(memory_ops)} memory operations")
    
    # Phase 3: Arithmetic operations
    print("\n=== Phase 3: Arithmetic Operations Analysis ===")
    arithmetic_ops = analyze_arithmetic_operations(ircfg_map)
    print(f"Found {len(arithmetic_ops)} arithmetic operations")
    
    # Phase 4: Comparisons
    print("\n=== Phase 4: Comparison Analysis ===")
    comparisons = analyze_comparisons(ircfg_map)
    print(f"Found {len(comparisons)} comparison operations")
    
    # Phase 5: Function calls
    print("\n=== Phase 5: Function Call Analysis ===")
    function_calls = analyze_function_calls(asm_cfg_map)
    print(f"Found {len(function_calls)} function calls")
    
    # Phase 6: Pattern detection
    print("\n=== Phase 6: Vulnerability Pattern Detection ===")
    vulnerabilities = detect_dangerous_patterns(memory_ops, arithmetic_ops, comparisons, function_calls)
    
    print(f"\nGENERIC VULNERABILITY REPORT:")
    print(f"Found {len(vulnerabilities)} potential issues")
    
    # Group by severity
    high_sev = [v for v in vulnerabilities if v['severity'] == 'HIGH']
    medium_sev = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
    low_sev = [v for v in vulnerabilities if v['severity'] == 'LOW']
    info_sev = [v for v in vulnerabilities if v['severity'] == 'INFO']
    
    if high_sev:
        print(f"\nHIGH SEVERITY ({len(high_sev)} issues):")
        for vuln in high_sev:
            print(f"  - {vuln['type']}: {vuln['details']['block']}")
    
    if medium_sev:
        print(f"\nMEDIUM SEVERITY ({len(medium_sev)} issues):")
        for vuln in medium_sev[:10]:  # Show first 10
            print(f"  - {vuln['type']}: {vuln['details'].get('instruction', vuln['details'])}")
    
    if low_sev:
        print(f"\nLOW SEVERITY ({len(low_sev)} issues):")
        print(f"  - {len(low_sev)} arithmetic operations found")
    
    if info_sev:
        print(f"\nINFORMATIONAL ({len(info_sev)} items):")
        constants = set()
        for vuln in info_sev:
            if 'constant_value' in vuln:
                constants.add(vuln['constant_value'])
        
        print(f"  - Found comparisons with constants: {sorted(list(constants))}")
    
    # Generate output files
    try:
        full_cfg = AsmCFG(mdis.loc_db)
        for blocks in viewvalues(asm_cfg_map):
            full_cfg += blocks
        
        with open('generic_analysis.dot', 'w') as f:
            f.write(full_cfg.dot(offset=True))
        print(f"\nSUCCESS: Control flow graph saved to generic_analysis.dot")
    except Exception as e:
        print(f"ERROR: Could not generate CFG: {e}")
    
    print(f"\n=== Analysis Complete ===")

if __name__ == "__main__":
    main()