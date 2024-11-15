import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprOp
from miasm.core.asmblock import AsmCFG
from miasm.ir.ir import IRCFG
from future.utils import viewvalues

binary_path = "/xxx/pcode-generator/tests/tinygo_index-out-of-range/tinygo_index-out-of-range"
main_address = 0x203685

def disassemble_and_execute_following_calls(machine, mdis, start_addr, follow_calls=True):
    """
    Disassembles and symbolically executes starting at start_addr.
    Follows calls recursively if follow_calls is True.
    """
    todo = [(mdis, start_addr)]
    done = set()
    ircfg_map = {}
    asm_cfg_map = {}

    while todo:
        mdis, addr = todo.pop(0)
        if addr in done:
            continue
        done.add(addr)

        # Disassemble and add to CFG
        asmcfg = mdis.dis_multiblock(addr)
        print(f"Disassembled at address: {hex(addr)}")
        lifter = machine.lifter_model_call(mdis.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
        ircfg_map[addr] = ircfg
        asm_cfg_map[addr] = asmcfg

        # Run symbolic execution on current CFG
        sym_exec_engine = SymbolicExecutionEngine(lifter)
        sym_exec_engine.run_at(ircfg, addr, step=True)
        print("Executed symbolic execution.")

        # Identify call instructions and follow them if enabled
        if follow_calls:
            for block in asmcfg.blocks:
                instr = block.get_subcall_instr()
                if not instr:
                    continue
                for dest in instr.getdstflow(mdis.loc_db):
                    if dest.is_loc():
                        offset = mdis.loc_db.get_location_offset(dest.loc_key)
                        todo.append((mdis, offset))

    all_asmcfg = IRCFG(None, mdis.loc_db)
    full_dsm = AsmCFG(mdis.loc_db)
    for blocks in viewvalues(asm_cfg_map):
        full_dsm += blocks

    open('graph_execflow.dot', 'w').write(full_dsm.dot(offset=True))

    return ircfg_map

def detect_index_out_of_bounds(ircfg_map):
    """
    Analyze the IRCFG to detect index out-of-bounds issues.
    """
    iob_violations = []

    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                written_elements = assignblk.get_w()
                read_elements = assignblk.get_r()

                # Check for out-of-bounds index on slices
                for src in read_elements:
                    if isinstance(src, ExprMem) and isinstance(src.ptr, ExprOp):
                        op = src.ptr

                        # Handle binary operations (e.g., addition)
                        if op.op == "+" and len(op.args) == 2:
                            base, offset = op.args
                            if isinstance(base, ExprInt) and isinstance(offset, ExprInt):
                                slice_size = base.arg
                                index = offset.arg
                                if index >= slice_size:
                                    iob_violations.append((lbl, assignblk))
                                    print(f"Index out of bounds detected at block {lbl}, instruction: {assignblk}")

                        # Fallback: Warn for unsupported complex operations
                        else:
                            print(f"Complex operation detected at block {lbl}, instruction: {assignblk}. Skipping for now.")

    return iob_violations


def main():
    loc_db = LocationDB()
    machine = Machine("x86_64")

    print(f"Loading binary from {binary_path}")
    with open(binary_path, "rb") as binary_file:
        container = Container.from_stream(binary_file, loc_db)

    # Initialize the disassembly engine
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    ircfg_map = disassemble_and_execute_following_calls(machine, mdis, main_address)

    # Detect index out-of-bounds
    iob_violations = detect_index_out_of_bounds(ircfg_map)

    if not iob_violations:
        print("No index out-of-bounds issues detected.")
    else:
        print(f"Detected {len(iob_violations)} potential index out-of-bounds issues.")
        for lbl, assignblk in iob_violations:
            print(f"Block: {lbl}, Instruction: {assignblk}")


if __name__ == "__main__":
    main()
