import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId, ExprSlice
from miasm.core.asmblock import AsmCFG
from future.utils import viewvalues

# Default configuration
DEFAULT_BINARY = "./../../omni-vuln4"
DEFAULT_ENTRY = 0x230530
MAX_ANALYSIS_DEPTH = 15

class GenericBinaryAnalyzer:
    def __init__(self, binary_path, entry_point=None, architecture="x86_64"):
        self.binary_path = binary_path
        self.entry_point = entry_point or DEFAULT_ENTRY
        self.architecture = architecture
        self.location_db = LocationDB()
        self.machine = Machine(architecture)
        self.container = None
        self.disassembler = None
        
    def load_binary(self):
        """Load and initialize the binary for analysis"""
        try:
            with open(self.binary_path, "rb") as f:
                self.container = Container.from_stream(f, self.location_db)
            self.disassembler = self.machine.dis_engine(self.container.bin_stream, loc_db=self.location_db)
            return True
        except Exception as e:
            print(f"Binary load failed: {e}")
            return False
    
    def discover_code_segments(self, start_address, max_segments=None):
        """Discover all reachable code segments from start address"""
        work_list = [start_address]
        discovered = set()
        ir_segments = {}
        asm_segments = {}
        segment_count = 0
        
        while work_list and (max_segments is None or segment_count < max_segments):
            current_addr = work_list.pop(0)
            
            if current_addr in discovered:
                continue
                
            discovered.add(current_addr)
            
            try:
                asm_cfg = self.disassembler.dis_multiblock(current_addr)
                lifter = self.machine.lifter_model_call(self.disassembler.loc_db)
                ir_cfg = lifter.new_ircfg_from_asmcfg(asm_cfg)
                
                ir_segments[current_addr] = ir_cfg
                asm_segments[current_addr] = asm_cfg
                segment_count += 1
                
                # Find additional code targets
                for block in asm_cfg.blocks:
                    for instruction in block.lines:
                        # Check for call/jump targets
                        if hasattr(instruction, 'getdstflow'):
                            for target in instruction.getdstflow(self.disassembler.loc_db):
                                if target.is_loc():
                                    target_addr = self.disassembler.loc_db.get_location_offset(target.loc_key)
                                    if target_addr and target_addr not in discovered:
                                        work_list.append(target_addr)
                
            except Exception as e:
                print(f"Analysis warning for {hex(current_addr)}: {e}")
                continue
        
        return ir_segments, asm_segments
    
    def extract_ir_operations(self, ir_segments):
        """Extract all intermediate representation operations"""
        all_operations = []
        
        for segment_addr, ir_cfg in ir_segments.items():
            for block_key, ir_block in ir_cfg.blocks.items():
                for assignment_set in ir_block:
                    for dest, src in assignment_set.items():
                        
                        operation = {
                            'segment': segment_addr,
                            'block': str(block_key),
                            'dest': str(dest),
                            'src': str(src),
                            'dest_class': dest.__class__.__name__,
                            'src_class': src.__class__.__name__
                        }
                        
                        # Extract operation-specific details
                        if isinstance(src, ExprOp):
                            operation['operator'] = src.op
                            operation['args'] = [str(arg) for arg in src.args]
                            operation['arg_count'] = len(src.args)
                        
                        if isinstance(src, ExprInt):
                            operation['constant'] = src.arg
                            operation['bit_size'] = src.size
                        
                        if isinstance(dest, ExprMem) or isinstance(src, ExprMem):
                            mem_ref = dest if isinstance(dest, ExprMem) else src
                            operation['mem_ptr'] = str(mem_ref.ptr)
                            operation['mem_size'] = mem_ref.size
                        
                        if isinstance(src, ExprCond):
                            operation['condition'] = str(src.cond)
                            operation['true_branch'] = str(src.src1)
                            operation['false_branch'] = str(src.src2)
                        
                        if isinstance(src, ExprSlice):
                            operation['slice_start'] = src.start
                            operation['slice_stop'] = src.stop
                            operation['slice_arg'] = str(src.arg)
                        
                        all_operations.append(operation)
        
        return all_operations
    
    def extract_assembly_data(self, asm_segments):
        """Extract assembly instruction data"""
        all_instructions = []
        
        for segment_addr, asm_cfg in asm_segments.items():
            for block in asm_cfg.blocks:
                for instr in block.lines:
                    instruction_data = {
                        'segment': segment_addr,
                        'block': str(block.loc_key),
                        'mnemonic': instr.name,
                        'full_instr': str(instr),
                        'arg_count': len(instr.args),
                        'args': [str(arg) for arg in instr.args]
                    }
                    all_instructions.append(instruction_data)
        
        return all_instructions
    
    def analyze_patterns(self, operations, instructions):
        """Analyze extracted data for patterns"""
        analysis = {
            'operation_stats': {},
            'instruction_stats': {},
            'constants_found': [],
            'memory_patterns': [],
            'control_flow_patterns': [],
            'data_flow_patterns': []
        }
        
        # Analyze IR operations
        op_types = {}
        constants = []
        
        for op in operations:
            op_class = op['src_class']
            op_types[op_class] = op_types.get(op_class, 0) + 1
            
            if 'constant' in op:
                constants.append(op['constant'])
            
            if 'operator' in op:
                operator = op['operator']
                if 'operators' not in analysis['operation_stats']:
                    analysis['operation_stats']['operators'] = {}
                analysis['operation_stats']['operators'][operator] = \
                    analysis['operation_stats']['operators'].get(operator, 0) + 1
            
            if 'mem_ptr' in op:
                analysis['memory_patterns'].append({
                    'type': 'memory_access',
                    'pointer': op['mem_ptr'],
                    'size': op['mem_size'],
                    'block': op['block']
                })
        
        analysis['operation_stats']['by_type'] = op_types
        analysis['constants_found'] = sorted(list(set(constants)))
        
        # Analyze assembly instructions
        instr_counts = {}
        for instr in instructions:
            mnemonic = instr['mnemonic']
            instr_counts[mnemonic] = instr_counts.get(mnemonic, 0) + 1
        
        analysis['instruction_stats']['by_mnemonic'] = instr_counts
        
        return analysis
    
    def generate_report(self, operations, instructions, analysis):
        """Generate comprehensive analysis report"""
        print("\n" + "="*60)
        print("GENERIC BINARY ANALYSIS REPORT")
        print("="*60)
        
        print(f"\nBinary: {self.binary_path}")
        print(f"Entry Point: {hex(self.entry_point)}")
        print(f"Architecture: {self.architecture}")
        
        print(f"\nExtraction Results:")
        print(f"  IR Operations: {len(operations)}")
        print(f"  Assembly Instructions: {len(instructions)}")
        
        print(f"\nOperation Type Distribution:")
        for op_type, count in sorted(analysis['operation_stats']['by_type'].items()):
            print(f"  {op_type}: {count}")
        
        if 'operators' in analysis['operation_stats']:
            print(f"\nOperator Usage:")
            sorted_ops = sorted(analysis['operation_stats']['operators'].items(), 
                              key=lambda x: x[1], reverse=True)
            for op, count in sorted_ops[:10]:
                print(f"  {op}: {count}")
        
        print(f"\nInstruction Distribution (Top 10):")
        sorted_instrs = sorted(analysis['instruction_stats']['by_mnemonic'].items(), 
                             key=lambda x: x[1], reverse=True)
        for mnemonic, count in sorted_instrs[:10]:
            print(f"  {mnemonic}: {count}")
        
        if analysis['constants_found']:
            print(f"\nConstants Found ({len(analysis['constants_found'])}):")
            displayed_constants = analysis['constants_found'][:20]
            print(f"  {displayed_constants}")
            if len(analysis['constants_found']) > 20:
                print(f"  ... and {len(analysis['constants_found']) - 20} more")
        
        print(f"\nMemory Access Patterns: {len(analysis['memory_patterns'])}")
        if analysis['memory_patterns']:
            print("  Sample patterns:")
            for pattern in analysis['memory_patterns'][:5]:
                print(f"    {pattern['type']}: {pattern['pointer']}")
    
    def save_control_flow_graph(self, asm_segments, filename="generic_analysis.dot"):
        """Save control flow graph to file"""
        try:
            combined_cfg = AsmCFG(self.location_db)
            for asm_cfg in asm_segments.values():
                combined_cfg += asm_cfg
            
            with open(filename, 'w') as f:
                f.write(combined_cfg.dot(offset=True))
            print(f"\nControl flow graph saved: {filename}")
        except Exception as e:
            print(f"CFG generation failed: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python generic_analyzer.py <binary> [entry_point_hex] [architecture]")
        print("Example: python generic_analyzer.py ./program 0x401000 x86_64")
        return
    
    binary_path = sys.argv[1]
    entry_point = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    architecture = sys.argv[3] if len(sys.argv) > 3 else "x86_64"
    
    print("Generic Binary Analysis Framework")
    print(f"Target: {binary_path}")
    
    analyzer = GenericBinaryAnalyzer(binary_path, entry_point, architecture)
    
    if not analyzer.load_binary():
        return
    
    print("Phase 1: Code Discovery")
    ir_segments, asm_segments = analyzer.discover_code_segments(
        analyzer.entry_point, MAX_ANALYSIS_DEPTH
    )
    print(f"Discovered {len(ir_segments)} code segments")
    
    print("Phase 2: Operation Extraction")
    operations = analyzer.extract_ir_operations(ir_segments)
    instructions = analyzer.extract_assembly_data(asm_segments)
    print(f"Extracted {len(operations)} operations, {len(instructions)} instructions")
    
    print("Phase 3: Pattern Analysis")
    analysis = analyzer.analyze_patterns(operations, instructions)
    
    analyzer.generate_report(operations, instructions, analysis)
    analyzer.save_control_flow_graph(asm_segments)
    
    print("\nAnalysis completed successfully")

if __name__ == "__main__":
    main()