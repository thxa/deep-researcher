# Hardware Interface Attacks

## 1. UART Serial Console Extraction

UART (Universal Asynchronous Receiver-Transmitter) is the most common debug interface on embedded devices. It provides a serial console for bootloader and OS interaction. Finding and accessing UART is often the first step in IoT hardware hacking.

### Identifying UART Pins

**Visual inspection**: Look for groups of 3-5 through-hole or SMD pads near the edge of the PCB. Common configurations:
- 4-pin header: VCC, TX, RX, GND (or just TX, RX, GND + no-connect)
- 3-pin header: TX, RX, GND
- Unpopulated header footprints (solder pads without pins)

**Multimeter method**: Set to continuity mode. Find GND first — pins connected to large copper pours, shield connectors, or USB port shell. Then measure voltage: TX and RX idle at logic levels (3.3V for most Cortex-M, 1.8V for some SoCs, rarely 5V for legacy devices).

**Logic analyzer method**: Connect a Saleae Logic or Sigrok-compatible analyzer to all unpopulated pins. Set to common baud rates (9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600). TX will show data bursts during boot.

**Pinout identification procedure**:

1. Identify GND: continuity to known ground points (USB shell, large copper pours).
2. Identify VCC: measures steady 3.3V or 1.8V. **Never connect this to your UART adapter.**
3. Identify TX: measures 3.3V (or logic level) idle, shows data during boot. Connect to your RX.
4. Identify RX: measures 0V or 3.3V idle. Connect to your TX.
5. Baud rate detection: Use `baudrate.py` or logic analyzer auto-detect. Alternatively, brute-force common rates:

```bash
for rate in 9600 19200 38400 57600 115200 230400 460800 921600; do
    echo "Trying $rate"
    stty -F /dev/ttyUSB0 $rate raw -echo -clocal
    timeout 3 cat /dev/ttyUSB0 &
    sleep 3
    kill %1 2>/dev/null
done
```

### UART Bootloader Interaction

**U-Boot**: The most common embedded bootloader. Accessible during the 1-5 second boot window.

```bash
# Common U-Boot interrupts
Hit any key to stop autoboot:  ← Press a key within the countdown

# Once in U-Boot:
=> printenv               # Show all environment variables
=> bootcmd                # Shows the boot command sequence
=> setenv bootdelay -1    # Disable boot delay (requires saveenv)
=> setenv init 'console=ttyS0,115200n8 root=/dev/mtdblock2'  # Modify boot args
=> bootm 0x9f010000        # Boot from memory address
=> nboot 0x80000000 0 0x200000  # Read NAND flash to RAM
=> mdw 0x80000000 0x100    # Memory dump (hex)
=> mw 0x80000000 0xdeadbeef 1  # Memory write

# Load kernel via TFTP (if network available):
=> setenv ipaddr 192.168.1.100
=> setenv serverip 192.168.1.200
=> tftpboot 0x80000000 vmlinux
=> bootm 0x80000000

# Modify root to init shell:
=> setenv bootargs console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh
=> boot
```

**CFE (Common Firmware Environment)**: Used in Broadcom-based devices (routers, modems).

```
CFE> boot -elf flash0:
CFE> boot -zelf flash0:  # Compressed ELF
CFE> show devices        # List available devices
CFE> flash -noheader 192.168.1.200:firmware.bin flash0:  # Flash new firmware
```

**RedBoot**: Used in older Marvell/Atheros devices.

```
RedBoot> fis list          # List flash images
RedBoot> fis create -l 0x100000 -e 0x80000000 newimage  # Create flash image
RedBoot> load -v -m tftp -h 192.168.1.200 firmware.bin  # Load via TFTP
RedBoot> go 0x80000000    # Execute
```

### Blocking Automatic Boot

If the boot window is too short or autoboot cannot be interrupted:

1. **Short the flash data pins**: Momentarily short pins on the NOR/NAND flash chip during boot read. This causes a CRC error, dropping to the bootloader.
2. **Remove boot media**: On devices with SD card boot, remove the card. U-Boot will drop to shell.
3. **Corrupt the environment**: Short the EEPROM/U-boot env partition (often `/dev/mtdX`). U-Boot detects corruption and drops to shell.
4. **Modify a resistor**: Some boards have a bootstrap resistor that selects boot mode. Changing it forces UART boot.

## 2. JTAG/SWD Debugging Interface Exploitation

### JTAG (IEEE 1149.1)

JTAG provides full debug and boundary scan access. The standard 4-signal interface:
- **TCK**: Test Clock
- **TMS**: Test Mode Select
- **TDI**: Test Data In
- **TDO**: Test Data Out
- **TRST** (optional): Test Reset

**Finding JTAG pins**: Use JTAGulator or JTAGenum (Arduino-based) to identify pin mappings:

```python
# JTAGenum on Raspberry Pi GPIO
# Scan all combinations of TCK, TMS, TDI, TDO on up to 8 pins
python3 jtagenum.py
# Or use JTAGulator:
# HV: 3.3V, Scan: JTAG pin scan mode
```

**OpenOCD configuration for common targets**:

```
# STM32F4 (Cortex-M4)
interface ft2232
ft2232_vid_pid 0x0403 0x6010
ft2232_layout jtagkey
transport select jtag
set CHIPNAME stm32f4x
jtag newtap stm32f4x cpu -irlen 4 -ircapture 0x1 -irmask 0xf -expected-id 0x2ba01477
target create stm32f4x.cpu cortex_m -chain-position stm32f4x.cpu
stm32f4x.cpu configure -work-area-phys 0x20000000 -work-area-size 0x10000

# ESP32 (Xtensa)
interface ftdi
ftdi_vid_pid 0x0403 0x6010
transport select jtag
set CHIPNAME esp32
jtag newtap esp32 cpu -irlen 5 -ircapture 0x1 -irmask 0x1 -expected-id 0x120034e5
target create esp32.cpu0 xtensa -chain-position esp32.cpu
```

**USEFUL JTAG COMMANDS (OpenOCD via telnet)**:

```
> halt                          # Halt CPU
> resume                         # Resume execution
> mdw 0x08000000 256             # Memory dump (word)
> mww 0x20000000 0xDEADBEEF     # Memory write
> flash probe 0                  # Identify flash bank
> flash dump 0 firmware.bin 0x0 0x100000  # Dump entire flash
> flash write_image erase unlock firmware.bin 0x08000000  # Write firmware
> bp 0x08000100 2 hw             # Set hardware breakpoint
> step                           # Single step
> reg                            # Show all registers
> reg pc 0x08000000              # Set register value
> cortex_m maskisr on            # Mask interrupts during stepping
```

### SWD (Serial Wire Debug)

SWD is ARM's 2-pin debug interface (SWDIO + SWCLK + GND). It's the dominant debug interface for Cortex-M processors.

**Pinout identification**:
- SWDIO: Bidirectional data (often has a pullup resistor)
- SWCLK: Clock (often has a pull-down)
- SWO: Optional trace output (single wire)
- RESET: Optional system reset

**SWD access with pyOCD**:

```bash
# List connected targets
pyocd list

# Dump flash
pyocd flash -t stm32f407ve save -o firmware_dump.bin 0x08000000 0x100000

# Erase and program
pyocd flash -t stm32f407ve erase_sector 0 0x08000000+0x10000
pyocd flash -t stm32f407ve program firmware_patched.bin 0x08000000

# GDB server
pyocd gdb -t stm32f407ve
# Then connect with arm-none-eabi-gdb:
(gdb) target remote :3333
(gdb) monitor halt
(gdb) x/256xw 0x08000000
(gdb) set *(uint32_t*)0x20000000 = 0x41424344
```

### Debug Protection Bypass

**ARM SWD Read-out Protection (RDP)**:

Level 0: No protection. Full debug access.
Level 1: Debug access to RAM and registers only. Flash read returns 0. Can be downgraded to Level 0, which **erases flash**.
Level 2: Permanent lockout. No debug access. Cannot be downgraded.

**Bypass techniques for Level 1**:

1. **RAM-based attack**: Even at RDP Level 1, the debugger can access SRAM. Load a small shellcode into RAM that copies flash to a communication interface (UART, SPI). Execute from RAM.

```c
// RAM-based flash dumper for STM32F4
// Loaded via OpenOCD into SRAM, executed from there
volatile uint32_t *flash = (volatile uint32_t *)0x08000000;
volatile uint32_t *usart1_dr = (volatile uint32_t *)0x40011004;
// Enable USART1 clock, configure pins, then:
for (int i = 0; i < 0x40000; i++) {
    *usart1_dr = flash[i];  // Send each word over UART
    while (!(*usart1_sr & 0x80));  // Wait for TX complete
}
```

2. **Voltage glitching on RDP check**: The MCU reads RDP level from flash option bytes during debug connect. A precisely timed voltage glitch during this read can cause the comparison to read as Level 0. This is device-specific and requires oscilloscope + glitcher setup.

3. **Bootrom vulnerability**: Some STM32 variants have known bootloader vulnerabilities. For example, STM32F4 boot ROM versions before a certain revision allow readout via bootloader commands even at RDP Level 1.

**NXP LPC IAP protection**: NXP uses CRP (Code Read Protection). CRP1 allows partial access via ISP (In-System Programming). CRP2 blocks all access except full erase. CRP3 is permanent lockout. A known bug in some LPC2148 revisions allows CRP1 bypass by sending specific IAP commands in quick succession.

## 3. SPI/I2C Bus Sniffing

### SPI Bus Sniffing

SPI (Serial Peripheral Interface) uses 4 signals: SCLK, MOSI, CS, MISO. It's used for MCU-to-flash, MCU-to-display, MCU-to-sensor communication.

**Sniffing with logic analyzer (Saleae / Sigrok)**:

```bash
# PulseView (sigrok) SPI decoder configuration:
# CLK: Channel 0
# MOSI: Channel 1 (data from MCU)
# MISO: Channel 2 (data from flash)
# CS: Channel 3

# Common SPI flash commands to watch for:
# 0x03 - READ (slow read)
# 0x0B - FAST_READ (fast read)
# 0x9F - JEDEC_ID (read manufacturer/device ID)
# 0x06 - WRITE_ENABLE
# 0x02 - PAGE_PROGRAM
# 0x05 - READ_STATUS_REGISTER
# 0xAB - RELEASE_FROM_DEEP_POWER_DOWN
```

**Desoldering and reading SPI flash**:

For NOR flash (W25Q64, MX25L12835, etc.):

1. Apply flux around the chip
2. Use hot air station at 300-350°C with appropriate nozzle
3. Gently lift chip once solder melts (don't apply force — wait for it)
4. Clean pads and chip legs with solder wick
5. Place chip in SOP-8 / SOP-16 socket on programmer (CH341A, Flashcat, Segger)
6. Read with `flashrom`:

```bash
# Read chip
flashrom -p ch341a_spi -r flash_dump.bin

# Verify read
flashrom -p ch341a_spi -v flash_dump.bin

# Identify chip
flashrom -p ch341a_spi --flash-size
```

For TSOP-48 NAND flash:

1. Use a TSOP-48 socket adapter
2. Read with a programmer supporting NAND (e.g., Xeltek SuperPro, EETools)
3. NAND flash requires ECC calculation and bad block handling

### I2C Bus Sniffing

I2C uses 2 signals: SDA (data) + SCL (clock). Used for sensors, EEPROMs, display controllers.

**Scanning I2C bus** (from embedded Linux):

```bash
# List I2C buses
i2cdetect -l

# Scan bus 0 for devices
i2cdetect -y 0

# Read from device at address 0x50 (typical EEPROM)
i2cget -y 0 0x50 0x00    # Read byte at offset 0
i2cdump -y 0 0x50        # Dump entire device
i2cset -y 0 0x50 0x00 0xAA  # Write byte
```

**Sniffing I2C** with Beagle I2C/SPI analyzer or logic analyzer:
- Monitor address + data for credential extraction (EEPROM often stores WiFi passwords, keys)
- Watch for authentication challenges (I2C TPM communication)

## 4. eMMC Debug Access

Embedded Multi-Media Controller (eMMC) is common in Cortex-A devices (routers, cameras, Android IoT). eMMC chips expose a standard MMC interface (CMD, CLK, DAT0-DAT7).

**Access methods**:

1. **eMMC test points**: Many PCBs have unpopulated eMMC test points near the chip. Identify CLK, CMD, DAT0 (1-bit mode requires only DAT0).

2. **ISP (In-System Programming) clip**: Use an eMMC ISP socket to connect without desoldering. Many commercial products (Medusa Box, EasyJTAG) support this.

3. **Desolder and socket**: Remove eMMC and read in a BGA socket adapter. Use hot air or IR rework station.

```bash
# Read eMMC via Linux MMC subsystem (if accessible as /dev/mmcblkX)
dd if=/dev/mmcblk0 of=emmc_dump.bin bs=4M

# Or partition by partition
dd if=/dev/mmcblk0boot0 of=boot0.bin bs=4M   # Boot partition 1
dd if=/dev/mmcblk0boot1 of=boot1.bin bs=4M   # Boot partition 2
dd if=/dev/mmcblk0rpmb of=rpmb.bin bs=4M      # RPMB (Replay Protected Memory Block)
```

**RPMB partition**: The Replay Protected Memory Block provides anti-replay storage. It requires a key programmed during manufacturing to read/write. Without the key, you can only detect its presence, not read its contents. However:
- The key may be derivable from device-unique information accessible via JTAG/SWD
- Some devices never program RPMB, leaving it with the default all-zero key

## 5. GPIO Pin Troll

Undocumented GPIO pins and test modes are a frequent attack surface. Many SoCs have:

- **Boot mode straps**: GPIO pins sampled at reset to select boot device (UART, SD, SPI, eMMC). Pulling these pins high/low forces alternative boot modes.
- **Factory test modes**: Pins that, when held at specific levels during boot, enable JTAG or other debug interfaces.
- **Secret key combos**: Sequences of GPIO levels that unlock hidden functionality.

**Methodology**:
1. Identify all unpopulated resistor pads near the SoC (bootstrap resistors)
2. Measure default levels during boot with oscilloscope
3. Toggle each pin (0→1, 1→0) during reset, observe UART output
4. Common test modes: NOR boot mode, USB device mode, JTAG unlock, factory console

**Case study: TP-Link router bootstrap**: Many TP-Link AR71xx-based routers have unpopulated resistor pads labeled Rxx. Bridging specific pads during boot forces the device into a factory test mode with full UART access and TFTP recovery.

**Case study: Samsung TV service menu**: Holding specific GPIO combinations during power-on enters the factory service menu, enabling USB debug, network configuration changes, and firmware downgrade.

## 6. Flash Chip Desoldering and Reading

### NOR Flash (SPI)

Common chips: Winbond W25Q series, Macronix MX25L series, Micron N25Q series.

| Package | Size | Pins | Protocol |
|---------|------|------|----------|
| SOP-8 | up to 16MB | 8 | SPI |
| SOP-16 | up to 128MB | 16 | SPI |
| WSON-8 | up to 64MB | 8 | SPI (no legs) |
| BGA | varies | varies | SPI/ONFI |

**Reading procedure**:

```bash
# Identify chip
flashrom -p ch341a_spi

# Full read
flashrom -p ch341a_spi -r chip_dump.bin

# Make multiple reads and compare (for reliability verification)
flashrom -p ch341a_spi -r chip_dump_1.bin
flashrom -p ch341a_spi -r chip_dump_2.bin
diff <(xxd chip_dump_1.bin) <(xxd chip_dump_2.bin)

# Write modified firmware
flashrom -p ch341a_spi -w modified_firmware.bin
```

**In-circuit reading** (without desoldering):
- Use a clip (Pomona SOIC-8 test clip, or 3M SMD clip) to connect to the chip while it's on the board
- Hold the MCU in reset (tie RESET pin to GND) to prevent bus contention
- Power off the board and rely on the programmer's VCC supply (3.3V)
- Or: use the board's power supply (risky — must prevent MCU from driving SPI lines)

### NAND Flash

NAND flash is more complex due to ECC, bad blocks, and OOB (Out-of-Band) data:

```bash
# NAND-specific read with OOB
nanddump --noecc --omtheader -f nand_dump.bin /dev/mtd0

# Read with ECC correction
nanddump -f nand_dump.bin /dev/mtd0

# For desoldered NAND, use BGA reader:
# Xeltek SuperPro 7500 or similar with NAND socket adapter
```

**NAND challenges**:
1. **ECC**: On-die ECC vs. controller ECC. Some NAND requires the SoC's ECC engine to read correctly.
2. **Bad blocks**: Factory-marked bad blocks must be preserved during reprogramming.
3. **ONFI vs. custom**: Most NAND follows ONFI, but some use custom command sets.

## 7. Glitching Attacks

### Voltage Glitching

Voltage glitching momentarily disrupts power to cause a fault (bit flip, instruction skip) at a precise moment. Common targets: secure boot verification, authentication checks, readout protection bypass.

**Equipment**:
- ChipWhisperer (open-source, Cortex-M focused)
- Eliptic's Glitcher (Riscure) (professional, multi-target)
- Custom FPGA-based glitchers (Atmega128 + MOSFET)

**Technique**:

1. **Identify the target instruction**: Use a bypass check as trigger (e.g., the jump instruction after a signature comparison).
2. **Establish timing**: Measure the target instruction's execution time with an oscilloscope monitoring a GPIO toggle or power pin.
3. **Glitch parameters**: Voltage drop (typically -0.5V to -3V below VCC), duration (5ns to 500ns), and phase (aligned to clock edge).
4. **Iterate**: Automated scripts sweep voltage and duration parameters.

```python
# ChipWhisperer example: Glitching STM32F4 secure boot
import chipwhisperer as cw

scope = cw.scope()
target = cw.target(scope)

# Configure glitch
scope.glitch.ext_width = 10.0       # Glitch width in percent
scope.glitch.ext_offset = 15.0      # Offset from trigger
scope.glitch.repeat = 1             # Single glitch pulse
scope.glitch.trigger_src = "manual" # Triggered when we say

# Sweep parameters
for width in range(1, 50):
    for offset in range(-50, 50):
        scope.glitch.ext_width = width
        scope.glitch.ext_offset = offset
        scope.glitch.trigger_src = "manual"
        target.flush()
        
        # Reset target and trigger
        scope.io.nrst = False
        time.sleep(0.1)
        scope.io.nrst = True
        
        # Check if glitch succeeded (e.g., past auth check)
        response = target.read()
        if "root@" in response or "#" in response:
            print(f"SUCCESS: width={width}, offset={offset}")
            break
```

### Clock Glitching

Injects extra clock edges or modifies clock frequency to cause setup/hold violations. More precise than voltage glitching for synchronous designs.

**Setup**: Replace the target's clock source with a controllable oscillator. Insert glitched clock pulses at specific points.

```python
# Clock glitch via ChipWhisperer
scope.glitch.clk_src = "target"       # Use target's clock as reference
scope.glitch.width = 2                 # 2 clock cycles wide
scope.glitch.offset = 42               # Offset from trigger in clock cycles
```

**Limitations**: Requires direct access to clock input. Many modern MCUs have internal PLLs that cannot be externally glitched. Works best on devices with external crystal oscillators.

### Electromagnetic (EM) Glitching

A coil antenna placed over the target IC induces a localized EM pulse, causing transient faults. Advantages: non-invasive (no PCB modification needed), can target specific chip areas.

**Setup**: EM probe (copper coil, 0.5-5mm diameter) positioned over the SoC die area. Pulse generator drives the coil. An XYZ translation stage enables precise positioning.

**Tuning**: Scan the die area in a grid pattern. At each position, try different pulse voltages and timings. Successful positions correspond to specific functional units (ALU, memory bus, register file).

**Use case**: EM glitch on STM32 TrustZone to skip the SAU check, allowing non-secure code to access secure memory.

## 8. Fault Injection

### Laser Fault Injection

Uses a focused laser pulse to ionize transistors on the die, causing bit flips. Requires die decapsulation (chemical etching of package) and a laser station. Extremely precise: can target individual SRAM cells or flip-flops.

**Decapsulation process**:
1. Mill or acid-etch the epoxy package to expose the die
2. For copper-wire packages: use fuming nitric acid at 80°C for 15-30 minutes, then clean with acetone and isopropanol
3. For flip-chip: die is already accessible from the top; only the heat spreader needs removal

**Laser setup**:
- Near-infrared (1064 nm) or green (532 nm) laser
- 20-100x microscope objective for focusing
- XYZ motorized stage with μm precision
- Pulse generator with ns timing resolution
- Cost: $50K-$200K for a complete station

**CVE-2021-30139**: Laser fault injection on an ESP32 bypassing secure boot V2. By glitching the RSA signature comparison during boot, the check can be bypassed, allowing unauthorized firmware execution.

### Electromagnetic Pulse Fault Injection

A high-voltage pulse through a coil generates a transient magnetic field that induces currents in the target chip. Less precise than laser but cheaper and non-destructive.

**Setup**:
- Coil antenna (5-15 mm diameter)
- Pulse generator (200-500V pulse)
- XY stage for positioning
- Oscilloscope for timing

**Case study**: Electromagnetic fault injection on a smart card to extract the private key from an RSA operation. By inducing a fault in one of the CRT (Chinese Remainder Theorem) computations, the full private key can be recovered from one faulty and one correct signature.

## 9. Side-Channel Attacks

### Power Analysis

**Simple Power Analysis (SPA)**: Direct observation of power consumption traces to identify instruction sequences. The power consumption of a CMOS circuit is proportional to switching activity.

```
SPA visual example (power trace):
   ___     ___     ___         ___________
  |   |   |   |   |   |       |           |    ← Square-and-multiply
  |   |   |   |   |   |       |           |       in RSA exponentiation
--|---|---|---|---|---|-------|-----------|--
  |   |   |   |   |   |       |           |
  |___|   |___|   |___|       |___________|

  S   M   S   M   S    S       M           ← Operations
```

SPA can distinguish:
- Conditional branches (if-then-else)
- Multi-precision arithmetic operations (different power profiles for multiply vs. square)
- Memory accesses (different power for cache hit vs. miss)

**Differential Power Analysis (DPA)**: Statistical analysis of many power traces to extract key bits. Each trace corresponds to one encryption operation. After collecting 100-1000 traces, correlate each time sample with a hypothesis about the key.

**DPA attack on AES**:

```python
# Simplified DPA on AES first round
import numpy as np

# Collect N traces, each corresponding to one AES encryption
traces = np.load('traces.npy')       # Shape: (N, num_samples)
plaintexts = np.load('plaintexts.npy') # Shape: (N, 16) - 16 bytes

# Target: first S-box output
# Hypothesis: key byte k (0-255), plaintext byte p_i
# Intermediate value: S-box[p_i XOR k]

for key_byte_guess in range(256):
    # Compute hypothetical intermediate values
    intermediate = np.array([sbox[p[0] ^ key_byte_guess] for p in plaintexts])
    
    # Compute hypothetical power consumption (Hamming weight model)
    hw = np.array([bin(v).count('1') for v in intermediate])
    
    # Correlate with actual power traces
    correlation = np.corrcoef(hw, traces.T)
    max_corr = np.max(np.abs(correlation))
    
    if max_corr > best_correlation:
        best_key_byte = key_byte_guess
        best_correlation = max_corr

# Repeat for each of the 16 key bytes
```

**Countermeasures**:
- Masking: XOR intermediate values with random masks (requires masked implementations)
- Shuffling: Randomize operation order (reduces but doesn't eliminate leakage)
- Constant-time implementations: Remove data-dependent branches and memory accesses

### Electromagnetic Emanation

EM probes capture the magnetic field generated by current flow in chip internals. Advantages over power analysis:
- Non-invasive (no resistor insertion needed)
- Can target specific chip regions (localized pickup)
- Works on devices where power measurement is impractical (battery-powered with integrated LDO)

**Equipment**: Near-field EM probe (Langer RF-U 5-2, custom coil), low-noise amplifier, SDR or oscilloscope (≥1 GS/s).

**TEMPEST**: Government standards for compromising emanations (NACSIM 5000, classified). Video display units, keyboards, and even LED indicators can leak information via EM.

## 10. IC Programmer Attacks

### EEPROM/Flash Programmers

Low-cost programmers (CH341A, WCH, Winford) can read and write many SOP-8/SOP-16 flash chips. The CH341A is the most common open-source programmer:

```bash
# CH341A programmer commands
# Read:
flashrom -p ch341a_spi -r dump.bin

# Read specific sector:
dd if=<(flashrom -p ch341a_spi -r -) bs=4096 skip=128 count=1 of=sector_128.bin

# Write:
flashrom -p ch341a_spi -w modified.bin

# Erase:
flashrom -p ch341a_spi -E
```

### In-Circuit Programmers

**SWD/ST-Link**: For ARM Cortex-M. Can read/program flash, SRAM, option bytes.

```bash
# STM32CubeProgrammer CLI
STM32_Programmer_CLI -c port=SWD -r32 0x08000000 0x10000 dump.bin   # Read flash
STM32_Programmer_CLI -c port=SWD -w32 firmware.bin 0x08000000        # Write flash
STM32_Programmer_CLI -c port=SWD -ob RDP=0xAA                       # Set RDP level 1
STM32_Programmer_CLI -c port=SWD -ob RDP=0xCC                       # Set RDP level 2 (permanent!)
```

**J-Link**: Universal JTAG/SWD probe. Supports a wide range of ARM cores.

```bash
# J-Link Commander
JLink> connect
Device> STM32F407VE
TIF> SWD
Speed> 4000
JLink> savebin firmware.bin 0x08000000 0x100000  # Read flash
JLink> loadbin modified.bin 0x08000000            # Write flash
```

## 11. Chip-Off Forensics

Chip-off forensics involves physically removing flash memory chips from a device and reading them independently. This is a last-resort technique when no software or debug access is available.

### Procedure

1. **Identify the chip**: Read the markings (e.g., "W25Q128JVSIQ" → Winbond 16MB SPI NOR flash).
2. **Desolder**:
   - Hot air: 300-350°C, gentle air flow, wait until chip lifts
   - Infrared rework: For BGA packages
   - Quick Chip: Chemical desoldering (DMF-based)
3. **Clean the chip**: Remove residual solder with solder wick and flux
4. **Program**: Place in appropriate socket (SOP-8, TSOP-48, BGA) and read with flashrom or专用 programmer
5. **Reconstruct**: Apply ECC correction, bad block mapping, and filesystem reconstruction

### BGA Package Handling

For eMMC BGA packages:
- Use a BGA rework station for desoldering
- Clean balls (or reball if necessary)
- Use a BGA socket adapter matching the package type (e.g., TFBGA-153 for common eMMC)
- Read with a BGA-compatible programmer

### Filesystem Reconstruction

After reading raw flash, reconstruct the filesystem:

```bash
# Identify filesystem signatures
binwalk flash_dump.bin

# For UBIFS (common on embedded Linux):
# Extract UBIFS from NAND image
ubireader_extract_info flash_dump.bin
ubireader_extract_files flash_dump.bin

# For JFFS2 (older embedded Linux):
jefferson flash_dump.bin -d jffs2_output/

# For SquashFS:
sasquatch -d squashfs_output/ flash_dump.bin

# For CramFS:
cramfsck -x cramfs_output/ flash_dump.bin
```

## 12. References

- *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg (No Starch Press)
- *Hardware Security: Design, Threats, and Safeguards* by Swaroop Ghosh et al.
- ChipWhisperer documentation: https://chipwhisperer.readthedocs.io
- NewAE Technology Glitch and Fault Injection tutorials
- NIST SP 800-147: BIOS Protection Guidelines
- ARM Debug Architecture Specification (ARM IHI 0031)
- IEEE 1149.1 (JTAG) Standard
- *Glitching the ESP32 Secure Boot* — limitedresults.com (CVE-2021-30139)
- Riscure Fault Injection tutorials and whitepapers
- *DPA on AES: 10 Years Later* — Jovan Dj. Golić

## References

1. *The Hardware Hacking Handbook* by Colin O'Flynn and Jasper van Woudenberg. No Starch Press (2022). ISBN: 978-1-59327-895-8.
2. *Hardware Security: Design, Threats, and Safeguards* by Swaroop Ghosh et al. CRC Press.
3. ChipWhisperer Documentation. NewAE Technology. https://chipwhisperer.readthedocs.io/
4. NewAE Technology Glitch and Fault Injection Tutorials. https://wiki.newae.com/
5. NIST SP 800-147: BIOS Protection Guidelines. National Institute of Standards and Technology.
6. ARM Debug Architecture Specification (ARM IHI 0031). ARM Limited.
7. IEEE 1149.1: Standard for Test Access Port and Boundary-Scan Architecture. IEEE.
8. *Glitching the ESP32 Secure Boot* — limitedresults.com (CVE-2021-30139).
9. Riscure Fault Injection Tutorials and Whitepapers. https://www.riscure.com/
10. *DPA on AES: 10 Years Later* — Jovan Dj. Golić.
11. *Practical IoT Hacking* by Fotios Chantzis et al. No Starch Press (2021).
12. OWASP IoT Top 10. https://owasp.org/www-project-top-ten/
13. NIST SP 800-183: Networks of Things. National Institute of Standards and Technology.
14. DEF CON IoT Village Presentations. https://iotvillage.org/
15. IEC 62443: Industrial Communication Networks — Network and System Security.
16. ARM TrustZone-M Technical Reference Manual. ARM Limited.
17. STM32 Reference Manual: RM0090. STMicroelectronics.
18. OpenOCD Documentation. https://openocd.org/
19. pyOCD Documentation. https://pyocd.io/
20. flashrom Documentation. https://flashrom.org/