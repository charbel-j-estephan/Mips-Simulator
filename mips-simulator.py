import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import re


class MIPSSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("MIPS Simulator")
        self.root.geometry("900x650")
        self.reset_simulator()

        self.create_ui()

        self.load_default_program()

    def reset_simulator(self):
        self.registers = {
            "$zero": 0,
            "$at": 0,
            "$v0": 0,
            "$v1": 0,
            "$a0": 0,
            "$a1": 0,
            "$a2": 0,
            "$a3": 0,
            "$t0": 0,
            "$t1": 0,
            "$t2": 0,
            "$t3": 0,
            "$t4": 0,
            "$t5": 0,
            "$t6": 0,
            "$t7": 0,
            "$s0": 0,
            "$s1": 0,
            "$s2": 0,
            "$s3": 0,
            "$s4": 0,
            "$s5": 0,
            "$s6": 0,
            "$s7": 0,
            "$t8": 0,
            "$t9": 0,
            "$k0": 0,
            "$k1": 0,
            "$gp": 0,
            "$sp": 0,
            "$fp": 0,
            "$ra": 0,
            "$hi": 0,
            "$lo": 0,
        }

        self.memory = {}

        self.program = []
        self.current_line = 0
        self.last_highlighted_line = None
        self.labels = {}
        self.execution_finished = False
        self.line_to_text_index = {}

    def create_ui(self):

        main_frame = tk.Frame(self.root, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        top_frame = tk.Frame(main_frame)
        top_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        code_frame = tk.LabelFrame(top_frame, text="MIPS Assembly Code")
        code_frame.pack(fill=tk.BOTH, expand=True)

        self.code_text = scrolledtext.ScrolledText(
            code_frame, wrap=tk.NONE, width=70, height=15, font=("Courier New", 10)
        )
        self.code_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.code_text.tag_configure("highlight", background="#ffff99")
        self.code_text.tag_configure("breakpoint", background="#ff9999")

        control_frame = tk.Frame(code_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.run_button = tk.Button(
            control_frame,
            text="Run All",
            command=self.run_program,
            width=10,
            bg="#4CAF50",
            fg="white",
        )
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.step_button = tk.Button(
            control_frame,
            text="Step",
            command=self.step_program,
            width=10,
            bg="#2196F3",
            fg="white",
        )
        self.step_button.pack(side=tk.LEFT, padx=5)

        self.reset_button = tk.Button(
            control_frame,
            text="Reset",
            command=self.reset_program,
            width=10,
            bg="#f44336",
            fg="white",
        )
        self.reset_button.pack(side=tk.LEFT, padx=5)

        status_frame = tk.LabelFrame(top_frame, text="Status")
        status_frame.pack(fill=tk.X, pady=(10, 0))

        self.status_var = tk.StringVar()
        self.status_var.set("Ready to execute. Click 'Step' or 'Run All'.")
        self.status_label = tk.Label(
            status_frame, textvariable=self.status_var, anchor=tk.W, padx=5, pady=5
        )
        self.status_label.pack(fill=tk.X)

        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        reg_frame = tk.LabelFrame(bottom_frame, text="Registers")
        reg_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        reg_scroll = tk.Scrollbar(reg_frame)
        reg_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.reg_tree = ttk.Treeview(
            reg_frame,
            yscrollcommand=reg_scroll.set,
            columns=("Register", "Value", "Hex"),
            show="headings",
            height=15,
        )
        self.reg_tree.column("Register", width=70)
        self.reg_tree.column("Value", width=70)
        self.reg_tree.column("Hex", width=90)
        self.reg_tree.heading("Register", text="Register")
        self.reg_tree.heading("Value", text="Value")
        self.reg_tree.heading("Hex", text="Hex")
        self.reg_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        reg_scroll.config(command=self.reg_tree.yview)

        mem_frame = tk.LabelFrame(bottom_frame, text="Memory")
        mem_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        mem_scroll = tk.Scrollbar(mem_frame)
        mem_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.mem_tree = ttk.Treeview(
            mem_frame,
            yscrollcommand=mem_scroll.set,
            columns=("Address", "Value", "Hex"),
            show="headings",
            height=15,
        )
        self.mem_tree.column("Address", width=90)
        self.mem_tree.column("Value", width=70)
        self.mem_tree.column("Hex", width=90)
        self.mem_tree.heading("Address", text="Address")
        self.mem_tree.heading("Value", text="Value")
        self.mem_tree.heading("Hex", text="Hex")
        self.mem_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        mem_scroll.config(command=self.mem_tree.yview)

    def load_default_program(self):
        default_code = """# Example MIPS program
# Calculate sum of numbers from 1 to 5
    addi $t0, $zero, 1    # i = 1
    addi $t1, $zero, 5    # limit = 5
    addi $t2, $zero, 0    # sum = 0
loop:
    add $t2, $t2, $t0     # sum = sum + i
    addi $t0, $t0, 1      # i = i + 1
    ble $t0, $t1, loop    # if i <= limit, goto loop
    sw $t2, 0($zero)      # store result in memory
    lw $a0, 0($zero)      # load result for printing
    mul $v0, $a0, $t1     # multiply by 5 for demo
    sub $s1, $v0, $a0     # subtract original value
    slt $s2, $a0, $v0     # set if a0 < v0
"""
        self.code_text.delete("1.0", tk.END)
        self.code_text.insert(tk.END, default_code)
        self.update_register_display()
        self.update_memory_display()

    def parse_program(self):
        code = self.code_text.get("1.0", tk.END)
        lines = code.split("\n")
        self.program = []
        self.labels = {}
        self.line_to_text_index = {}

        program_line = 0
        text_line = 1
        for line in lines:
            clean_line = re.sub(r"#.*$", "", line).strip()

            if not clean_line:
                text_line += 1
                continue

            label_match = re.match(r"^(\w+):\s*(.*)", clean_line)
            if label_match:
                label = label_match.group(1)
                rest_of_line = label_match.group(2).strip()
                self.labels[label] = program_line

                if rest_of_line:
                    self.line_to_text_index[program_line] = text_line
                    self.program.append(rest_of_line)
                    program_line += 1
            else:
                self.line_to_text_index[program_line] = text_line
                self.program.append(clean_line)
                program_line += 1

            text_line += 1

        if self.program:
            self.status_var.set(
                f"Program parsed: {len(self.program)} instructions, {len(self.labels)} labels"
            )
        else:
            self.status_var.set("Warning: No valid instructions found")

    def update_register_display(self):
        for item in self.reg_tree.get_children():
            self.reg_tree.delete(item)

        for reg, value in self.registers.items():
            hex_value = f"0x{value & 0xffffffff:08x}"
            self.reg_tree.insert("", tk.END, values=(reg, value, hex_value))

    def update_memory_display(self):
        for item in self.mem_tree.get_children():
            self.mem_tree.delete(item)

        for addr in sorted(self.memory.keys()):
            if self.memory[addr] != 0:
                value = self.memory[addr]
                hex_value = f"0x{value & 0xffffffff:08x}"
                self.mem_tree.insert(
                    "", tk.END, values=(f"0x{addr:08x}", value, hex_value)
                )

    def highlight_current_line(self):
        if self.last_highlighted_line is not None:
            self.code_text.tag_remove(
                "highlight",
                f"{self.last_highlighted_line}.0",
                f"{self.last_highlighted_line}.end",
            )

        if self.current_line in self.line_to_text_index:
            line_index = self.line_to_text_index[self.current_line]
            self.code_text.tag_add("highlight", f"{line_index}.0", f"{line_index}.end")
            self.code_text.see(f"{line_index}.0")
            self.last_highlighted_line = line_index

    def reset_program(self):
        self.reset_simulator()

        if self.last_highlighted_line is not None:
            self.code_text.tag_remove(
                "highlight",
                f"{self.last_highlighted_line}.0",
                f"{self.last_highlighted_line}.end",
            )
            self.last_highlighted_line = None

        self.update_register_display()
        self.update_memory_display()
        self.status_var.set("Program reset. Ready to execute.")

    def run_program(self):
        if not self.program:
            self.parse_program()

        if not self.program:
            return

        try:
            while not self.execution_finished and self.current_line < len(self.program):
                self.execute_instruction()

            if self.execution_finished:
                self.status_var.set("Program execution completed")
                messagebox.showinfo(
                    "Execution Complete", "Program execution has finished successfully."
                )
            else:
                self.status_var.set(
                    f"Reached end of program at line {self.current_line}"
                )
                messagebox.showinfo(
                    "End of Program",
                    f"Reached the end of program at line {self.current_line}.",
                )

            self.update_register_display()
            self.update_memory_display()
        except Exception as e:
            messagebox.showerror(
                "Execution Error", f"Error while running program: {str(e)}"
            )

    def step_program(self):
        if not self.program:
            self.parse_program()

        if not self.program:
            return

        if not self.execution_finished and self.current_line < len(self.program):
            self.highlight_current_line()
            instruction = self.program[self.current_line]

            try:
                self.status_var.set(f"Executing: {instruction}")
                self.execute_instruction()
                self.update_register_display()
                self.update_memory_display()

                if self.execution_finished:
                    messagebox.showinfo(
                        "Execution Complete",
                        "Program execution has finished successfully.",
                    )
            except Exception as e:
                messagebox.showerror(
                    "Execution Error", f"Error executing instruction: {str(e)}"
                )
        else:
            self.status_var.set("End of program reached")
            messagebox.showinfo("End of Program", "End of program reached.")

    def execute_instruction(self):
        if self.current_line >= len(self.program):
            self.execution_finished = True
            return

        instruction = self.program[self.current_line]
        parts = [p.strip() for p in re.split(r",|\s+", instruction) if p.strip()]

        if not parts:
            self.current_line += 1
            return

        opcode = parts[0]
        self.execute_opcode(opcode, parts)

    def execute_opcode(self, opcode, parts):
        next_line = self.current_line + 1

        if opcode == "add" and len(parts) >= 4:
            rd, rs, rt = parts[1], parts[2], parts[3]
            self.registers[rd] = self.registers[rs] + self.registers[rt]

        elif opcode == "addi" and len(parts) >= 4:
            rt, rs, imm = parts[1], parts[2], int(parts[3])
            self.registers[rt] = self.registers[rs] + imm

        elif opcode == "sub" and len(parts) >= 4:
            rd, rs, rt = parts[1], parts[2], parts[3]
            self.registers[rd] = self.registers[rs] - self.registers[rt]

        elif opcode == "mul" and len(parts) >= 4:
            rd, rs, rt = parts[1], parts[2], parts[3]
            result = self.registers[rs] * self.registers[rt]
            self.registers[rd] = result & 0xFFFFFFFF

        elif opcode == "slt" and len(parts) >= 4:
            rd, rs, rt = parts[1], parts[2], parts[3]
            self.registers[rd] = 1 if self.registers[rs] < self.registers[rt] else 0
        elif opcode == "sll" and len(parts) >= 4:
            rd, rt, shamt = parts[1], parts[2], int(parts[3])
            self.registers[rd] = (self.registers[rt] << shamt) & 0xFFFFFFFF

        elif opcode == "srl" and len(parts) >= 4:
            rd, rt, shamt = parts[1], parts[2], int(parts[3])
            self.registers[rd] = (self.registers[rt] >> shamt) & 0xFFFFFFFF

        elif opcode == "lw" and len(parts) >= 3:
            rt = parts[1]
            mem_ref = parts[2]
            match = re.match(r"(-?\d+)\((\$\w+)\)", mem_ref)
            if match:
                offset, rs = int(match.group(1)), match.group(2)
                addr = self.registers[rs] + offset
                if addr in self.memory:
                    self.registers[rt] = self.memory[addr]
                else:
                    self.registers[rt] = 0
        elif opcode == "sw" and len(parts) >= 3:
            rt = parts[1]
            mem_ref = parts[2]
            match = re.match(r"(-?\d+)\((\$\w+)\)", mem_ref)
            if match:
                offset, rs = int(match.group(1)), match.group(2)
                addr = self.registers[rs] + offset
                self.memory[addr] = self.registers[rt]

        elif opcode == "beq" and len(parts) >= 4:
            rs, rt, label = parts[1], parts[2], parts[3]
            if self.registers[rs] == self.registers[rt]:
                if label in self.labels:
                    next_line = self.labels[label]
                else:
                    messagebox.showerror("Error", f"Undefined label: {label}")

        elif opcode == "bne" and len(parts) >= 4:
            rs, rt, label = parts[1], parts[2], parts[3]
            if self.registers[rs] != self.registers[rt]:
                if label in self.labels:
                    next_line = self.labels[label]
                else:
                    messagebox.showerror("Error", f"Undefined label: {label}")

        elif opcode == "j" and len(parts) >= 2:
            label = parts[1]
            if label in self.labels:
                next_line = self.labels[label]
            else:
                messagebox.showerror("Error", f"Undefined label: {label}")

        elif opcode == "jr" and len(parts) >= 2:
            rs = parts[1]
            if rs in self.registers:
                next_line = self.registers[rs]

        elif opcode == "jal" and len(parts) >= 2:
            label = parts[1]
            if label in self.labels:
                self.registers["$ra"] = self.current_line + 1
                next_line = self.labels[label]
            else:
                messagebox.showerror("Error", f"Undefined label: {label}")

        elif opcode == "syscall":
            service = self.registers["$v0"]
            if service == 1:
                value = self.registers["$a0"]
                messagebox.showinfo("Syscall", f"Print Integer: {value}")
            elif service == 4:
                messagebox.showinfo(
                    "Syscall", "Print String (not implemented in this simulator)"
                )
            elif service == 10:
                self.execution_finished = True
                self.status_var.set("Program terminated with syscall exit")
                messagebox.showinfo(
                    "Program Exit", "Program terminated with syscall exit command."
                )
            else:
                messagebox.showinfo("Syscall", f"Unknown syscall code: {service}")

        else:
            messagebox.showwarning("Warning", f"Unsupported instruction: {opcode}")

        self.current_line = next_line

        self.registers["$zero"] = 0


if __name__ == "__main__":
    root = tk.Tk()
    app = MIPSSimulator(root)
    root.mainloop()
