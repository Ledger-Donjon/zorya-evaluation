import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId
from miasm.core.asmblock import AsmCFG
from future.utils import viewvalues

# Configuration
binary_path = "./../../panic-index"
entry_point = 0x22c0f0

def extract_all_operations(ircfg_map):
    """
    Extract all operations from IR without filtering or assumptions
    """
    operations = []
    
    for cfg_addr, ircfg in ircfg_map.items():
        for block_label, ir_block in ircfg.blocks.items():
            for assignment_block in ir_block:
                for destination, source in assignment_block.items():
                    
                    operation_data = {
                        'cfg_address': cfg_addr,
                        'block': block_label,
                        'destination': str(destination),
                        'source': str(source),
                        'dest_type': type(destination).__name__,
                        'source_type': type(source).__name__
                    }
                    
                    # Extract additional details based on expression types
                    if isinstance(source, ExprOp):
                        operation_data['operation'] = source.op
                        operation_data['operands'] = [str(arg) for arg in source.args]
                    
                    if isinstance(source, ExprInt):
                        operation_data['immediate_value'] = source.arg
                    
                    if isinstance(destination, ExprMem) or isinstance(source, ExprMem):
                        mem_expr = destination if isinstance(destination, ExprMem) else source
                        operation_data['memory_address'] = str(mem_expr.ptr)
                    
                    operations.append(operation_data)
    
    return operations

def extract_assembly_instructions(asm_cfg_map):
    """
    Extract raw assembly instructions
    """
    instructions = []
    
    for cfg_addr, asm_cfg in asm_cfg_map.items():
        for block in asm_cfg.blocks:
            for instruction in block.lines:
                instructions.append({
                    'cfg_address': cfg_addr,
                    'block': block.loc_key,
                    'instruction': str(instruction),
                    'mnemonic': instruction.name,
                    'args': [str(arg) for arg in instruction.args]
                })
    
    return instructions

def analyze_data_patterns(operations):
    """
    Analyze patterns in the extracted operations
    """
    patterns = {
        'memory_operations': [],
        'arithmetic_operations': [],
        'comparison_operations': [],
        'immediate_values': [],
        'register_operations': []
    }
    
    for op in operations:
        # Memory operations
        if 'memory_address' in op:
            patterns['memory_operations'].append(op)
        
        # Arithmetic operations
        if 'operation' in op and op['operation'] in ['+', '-', '*', '/', '<<', '>>', '&', '|', '^']:
            patterns['arithmetic_operations'].append(op)
        
        # Comparison operations
        if 'operation' in op and op['operation'] in ['==', '!=', '<', '>', '<=', '>=', 'CMP']:
            patterns['comparison_operations'].append(op)
        
        # Immediate values
        if 'immediate_value' in op:
            patterns['immediate_values'].append(op['immediate_value'])
        
        # Register operations
        if op['dest_type'] == 'ExprId' or op['source_type'] == 'ExprId':
            patterns['register_operations'].append(op)
    
    return patterns

def analyze_instruction_patterns(instructions):
    """
    Analyze patterns in assembly instructions
    """
    patterns = {
        'call_instructions': [],
        'jump_instructions': [],
        'compare_instructions': [],
        'move_instructions': [],
        'unique_mnemonics': set()
    }
    
    for instr in instructions:
        mnemonic = instr['mnemonic'].upper()
        patterns['unique_mnemonics'].add(mnemonic)
        
        if 'CALL' in mnemonic:
            patterns['call_instructions'].append(instr)
        
        if any(jump in mnemonic for jump in ['JMP', 'JE', 'JNE', 'JL', 'JG', 'JLE', 'JGE']):
            patterns['jump_instructions'].append(instr)
        
        if 'CMP' in mnemonic:
            patterns['compare_instructions'].append(instr)
        
        if 'MOV' in mnemonic:
            patterns['move_instructions'].append(instr)
    
    return patterns

def disassemble_binary(machine, mdis, start_address, max_depth=10):
    """
    Generic binary disassembly
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
            print(f"Warning: Could not analyze address {hex(address)}: {e}")
            continue
    
    return ir_cfgs, asm_cfgs

def generate_statistics(patterns, instruction_patterns):
    """
    Generate statistical summary
    """
    stats = {
        'total_ir_operations': len(patterns['memory_operations']) + 
                             len(patterns['arithmetic_operations']) + 
                             len(patterns['comparison_operations']) + 
                             len(patterns['register_operations']),
        'memory_operations': len(patterns['memory_operations']),
        'arithmetic_operations': len(patterns['arithmetic_operations']),
        'comparison_operations': len(patterns['comparison_operations']),
        'unique_immediate_values': len(set(patterns['immediate_values'])),
        'call_instructions': len(instruction_patterns['call_instructions']),
        'jump_instructions': len(instruction_patterns['jump_instructions']),
        'compare_instructions': len(instruction_patterns['compare_instructions']),
        'unique_mnemonics': len(instruction_patterns['unique_mnemonics'])
    }
    
    return stats

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyzer.py <binary_path> [entry_point_hex]")
        sys.exit(1)
    
    global binary_path, entry_point
    binary_path = sys.argv[1]
    
    if len(sys.argv) > 2:
        entry_point = int(sys.argv[2], 16)
    
    print("Universal Binary Analyzer")
    print(f"Target: {binary_path}")
    print(f"Entry: {hex(entry_point)}")
    print()
    
    # Initialize framework
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
    print("Phase 1: Disassembly")
    ir_cfgs, asm_cfgs = disassemble_binary(machine, disassembler, entry_point)
    print(f"Analyzed {len(ir_cfgs)} code segments")
    
    # Extract operations
    print("Phase 2: Operation Extraction")
    operations = extract_all_operations(ir_cfgs)
    print(f"Extracted {len(operations)} IR operations")
    
    # Extract instructions
    print("Phase 3: Instruction Extraction")
    instructions = extract_assembly_instructions(asm_cfgs)
    print(f"Extracted {len(instructions)} assembly instructions")
    
    # Pattern analysis
    print("Phase 4: Pattern Analysis")
    operation_patterns = analyze_data_patterns(operations)
    instruction_patterns = analyze_instruction_patterns(instructions)
    
    # Generate statistics
    stats = generate_statistics(operation_patterns, instruction_patterns)
    
    # Report results
    print()
    print("ANALYSIS RESULTS")
    print("=" * 50)
    
    print(f"Total IR Operations: {stats['total_ir_operations']}")
    print(f"Memory Operations: {stats['memory_operations']}")
    print(f"Arithmetic Operations: {stats['arithmetic_operations']}")
    print(f"Comparison Operations: {stats['comparison_operations']}")
    print(f"Unique Immediate Values: {stats['unique_immediate_values']}")
    print()
    
    print(f"Call Instructions: {stats['call_instructions']}")
    print(f"Jump Instructions: {stats['jump_instructions']}")
    print(f"Compare Instructions: {stats['compare_instructions']}")
    print(f"Unique Mnemonics: {stats['unique_mnemonics']}")
    print()
    
    # Show immediate values found
    if operation_patterns['immediate_values']:
        unique_values = sorted(set(operation_patterns['immediate_values']))
        print(f"Immediate Values Found: {unique_values[:20]}...")  # Show first 20
        print()
    
    # Show sample operations
    if operation_patterns['comparison_operations']:
        print("Sample Comparison Operations:")
        for i, op in enumerate(operation_patterns['comparison_operations'][:5]):
            print(f"  {i+1}. {op['operation']} at block {op['block']}")
        print()
    
    if operation_patterns['memory_operations']:
        print("Sample Memory Operations:")
        for i, op in enumerate(operation_patterns['memory_operations'][:5]):
            op_type = "write" if op['dest_type'] == 'ExprMem' else "read"
            print(f"  {i+1}. Memory {op_type} at {op['memory_address']}")
        print()
    
    # Generate control flow graph
    try:
        combined_cfg = AsmCFG(location_db)
        for cfg in asm_cfgs.values():
            combined_cfg += cfg
        
        with open('analysis_output.dot', 'w') as output_file:
            output_file.write(combined_cfg.dot(offset=True))
        print("Control flow graph saved to: analysis_output.dot")
    except Exception as error:
        print(f"Could not generate CFG: {error}")
    
    print("Analysis complete")

if __name__ == "__main__":
    main()