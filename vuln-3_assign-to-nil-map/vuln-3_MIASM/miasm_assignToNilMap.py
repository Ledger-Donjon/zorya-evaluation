import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprMem, ExprInt
from miasm.core.asmblock import AsmCFG
from miasm.ir.ir import IRCFG
from future.utils import viewvalues

binary_path = "/xxx/pcode-generator/tests/tinygo_assign-to-nil-map/tinygo_assign-to-nil-map"
main_address = 0x2036ee  # Replace with the main function address of your binary


def disassemble_and_execute_following_calls(machine, mdis, start_addr, follow_calls=True):
    """
    Disassembles and symbolically executes starting at start_addr.
    Follows calls recursively if follow_calls is True.
    Generates the CFG for visualization.
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

    # Generate a combined CFG graph
    full_dsm = AsmCFG(mdis.loc_db)
    for blocks in viewvalues(asm_cfg_map):
        full_dsm += blocks

    with open('graph_execflow.dot', 'w') as f:
        f.write(full_dsm.dot(offset=True))
    print("CFG graph written to 'graph_execflow.dot'.")

    return ircfg_map


def detect_nil_map_assignment(ircfg_map):
    """
    Analyze the IRCFG to detect nil map assignments.
    """
    nil_map_violations = []

    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                written_elements = assignblk.get_w()
                read_elements = assignblk.get_r()

                # Check for assignments to nil maps
                for dst in written_elements:
                    if isinstance(dst, ExprMem) and isinstance(dst.ptr, ExprInt):
                        # Identify if memory address corresponds to a nil map (address 0)
                        if dst.ptr.arg == 0:  # Address 0 indicates a nil map in this context
                            nil_map_violations.append((lbl, assignblk))
                            print(f"Nil map assignment detected at block {lbl}, instruction: {assignblk}")

    return nil_map_violations


def main():
    loc_db = LocationDB()
    machine = Machine("x86_64")

    print(f"Loading binary from {binary_path}")
    with open(binary_path, "rb") as binary_file:
        container = Container.from_stream(binary_file, loc_db)

    # Initialize the disassembly engine
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    ircfg_map = disassemble_and_execute_following_calls(machine, mdis, main_address)

    # Detect nil map assignments
    nil_map_violations = detect_nil_map_assignment(ircfg_map)

    if not nil_map_violations:
        print("No nil map assignments detected.")
    else:
        print(f"Detected {len(nil_map_violations)} potential nil map assignments.")
        for lbl, assignblk in nil_map_violations:
            print(f"Block: {lbl}, Instruction: {assignblk}")


if __name__ == "__main__":
    main()
