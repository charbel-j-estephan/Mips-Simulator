# MIPS Web Visualizer

## Overview
MIPS Web Visualizer is a browser-based tool designed to help users understand and analyze the execution of MIPS assembly code through an interactive visual representation. The simulator allows step-by-step execution of instructions, making it an excellent learning and debugging tool for students and professionals working with MIPS architecture.

## Features
- **Web-based Execution:** No installation required, runs directly in the browser.
- **Interactive Code Editor:** Write, modify, and execute MIPS assembly code in real time.
- **Step-by-Step Execution:** Run the program one instruction at a time to track execution flow.
- **Register and Memory Visualization:** Observe real-time changes in registers and memory.
- **Terminal Output Simulation:** Supports syscalls for output and input operations.
- **Preloaded Example Code:** Helps beginners understand the structure of MIPS programs.
- **Highlighting Active Instructions:** Visually tracks the execution progress within the code editor.

## Installation & Usage
Since MIPS Web Visualizer is a web-based tool, it does not require installation. However, to run it locally:

### Running Online
MIPS Web Visualizer can be accessed and used directly in a browser without downloading or setting up anything. Simply visit:
```
https://charbel-j-estephan.github.io/Mips-Web-Simulator/
```
This ensures that you always have the latest version without needing to update manually.

### Running Locally
1. Clone the repository:
   ```sh
   git clone <https://github.com/charbel-j-estephan/Mips-Simulator>
   cd mips-web-visualizer
   ```
2. Open `index.html` in a web browser.

## How to Use
1. **Load or Write Code:** Use the integrated editor to write or load MIPS assembly code.
2. **Run Execution:**
   - Click `Run All` to execute the entire program at once.
   - Click `Step` to execute the program one instruction at a time.
3. **Track Execution:**
   - View real-time updates in the **Registers** and **Memory** sections.
   - Monitor program output in the **Terminal** section.
   - Highlight active instructions in the code editor.
4. **Reset Program:** Click `Reset` to clear the state and reload the program.

## Supported Instructions
MIPS Web Visualizer supports a subset of MIPS assembly instructions, including:
- **Arithmetic & Logical:** `add`, `addi`, `sub`, `mul`, `div`, `and`, `or`, `xor`, `nor`
- **Memory Operations:** `lw`, `sw`, `lb`, `sb`, `lh`, `sh`
- **Branching & Jumping:** `beq`, `bne`, `j`, `jal`, `jr`
- **Load & Store:** `la`, `li`, `lui`
- **Syscalls:** Supports `syscall` for basic input/output functions.

## Future Improvements
- **Extended Instruction Set:** Support for floating-point and advanced MIPS instructions.
- **Breakpoints & Watchpoints:** Enable better debugging features.
- **Enhanced UI/UX:** Improve visualization of execution flow.
- **File Upload Support:** Load and save MIPS programs more conveniently.
- **Assembly Parsing Improvements:** Better syntax highlighting and error handling.

## Contributing
We welcome contributions from the community! If you encounter bugs, have feature requests, or would like to contribute improvements, please open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

## Acknowledgments
This project is inspired by various MIPS simulation tools and aims to provide an easy-to-use, educational platform for learning MIPS assembly programming.

