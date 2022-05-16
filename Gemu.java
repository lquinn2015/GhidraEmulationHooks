import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.LockException;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;

public class Gemu  extends GhidraScript
{
	EmulatorHelper gemu;
	HashMap<Address, ArrayList<GemuScript>> hookList;
	
	static long gemu_StackAddr = 0xA00_0000;
	static long gemu_HeapAddr = 0xB00_0000;
	
	
	long StartAddress = 0x100d1c;
	Address RETURN_ADDR;
	
	long OpenAddress = 0x100980;
	long ReadAddress = 0x0100a30;
	long MallocAddress = 0x100990;
	
	long printfAddress = 0x0100a50;
	
	long cdataAddress = 0x7000000;
	
	
	@Override
	protected void run() throws Exception {
		
		gemu = new EmulatorHelper(currentProgram);
		
		RETURN_ADDR = toAddr(0);
		
		// Register 
		gemu.writeRegister("pc", StartAddress);
		gemu.writeRegister("x30", 0);
		gemu.writeRegister("sp", gemu_StackAddr+0x1000);
		gemu.registerDefaultCallOtherCallback(new NopCallback()); // ignore unknown pcode
		printState();

		// Setup some basic hooks
		for(Function func: currentProgram.getFunctionManager().getFunctions(true)){
			AddHook(func.getEntryPoint(), new GemuScript(func.getName()+"_naming", ()->printFunctionStart()));	
		}
		
		AddHook(toAddr(OpenAddress), new GemuScript("OpenHook", ()->QuickReturn(0)));
		AddHook(toAddr(ReadAddress), new GemuScript("ReadHook", ()->HandleRead()));
		
		AddHook(toAddr(MallocAddress), new GemuScript("MallocHook", ()->HandleMalloc()));
		AddHook(toAddr(0x0100970), new GemuScript("fclose", ()->QuickReturn(0)));
		
		AddHook(toAddr(printfAddress), new GemuScript("PrintfHook", ()->LogPrintf()));
		AddHook(toAddr(printfAddress), new GemuScript("OpenHook", ()->QuickReturn(0)));
		
		AddHook(toAddr(0x0400290), new GemuScript("memset ignore", ()->QuickReturn(0)));
		
		gemu.run(monitor);
		while(!monitor.isCancelled()) {
		
			Address execAddr = gemu.getExecutionAddress();
//			printState();
			if(execAddr.equals(RETURN_ADDR)) {
				return; // we are done
			}
			boolean shouldContinue = processBreakpointAndPatches(execAddr);
			if(!shouldContinue) {
				return;
			}
			gemu.run(monitor);		
		}
	}
	
	int readDataIdx = 0;
	private boolean HandleRead() 
	{ // fread (buf,1,amount,fd)
		Address bufAddr = toAddr(gemu.readRegister("x0").longValue());
		int amt = gemu.readRegister("x2").intValue();
		byte[] cdata = gemu.readMemory(toAddr(cdataAddress).add(readDataIdx), amt);
		readDataIdx += amt;
		gemu.writeMemory(bufAddr, cdata);
		gemu.writeRegister("pc", gemu.readRegister("x30").clearBit(0));
		return true; // keep going
	}
	
	
	static long nextHeapAddr = gemu_HeapAddr;
	private boolean HandleMalloc(){
		
		long sz = gemu.readRegister("x0").longValue(); // size
		gemu.writeRegister("x0", new BigInteger(Long.toHexString(nextHeapAddr), 16)); // insert the first thing
		nextHeapAddr += sz;
		gemu.writeRegister("pc", gemu.readRegister("x30").clearBit(0));
		
		return true;
	}
	
	
	// your implementation my vary if params get passed on the stack that is harder
	private boolean LogPrintf()
	{ // char*,  arg1, arg2, ...
		
		
		printState();
		String fstr = gemu.readNullTerminatedString(toAddr(gemu.readRegister("x0").longValue()), 0x100);
		int idx = 0;
		int strlen = fstr.length();
		int carg = 1;
		
		Matcher regex = Pattern.compile("%[sld]+", Pattern.CASE_INSENSITIVE).matcher(fstr);
		ArrayList<String> results = new ArrayList<>(); 
		while(regex.find()) {
			String s = regex.group();
			if(s.equals("%s")) {
				byte[] b = gemu.readMemory(toAddr(gemu.readRegister("x1").longValue()), 0x1000);
				results.add(gemu.readNullTerminatedString(toAddr(gemu.readRegister("x" + carg++).longValue()), 0x100));		
			} else { //if (s.equals("%ld")) {
				results.add(gemu.readRegister("x" + carg++).toString());
			} 
		}
		println(fstr);
		for(String s : results) {
			println("	" + s);
		}
		gemu.writeRegister("pc", gemu.readRegister("x30").clearBit(0));
		return true;
	}

	
	private class GemuScript implements Comparable<GemuScript> 
	{

		String name;
		Callable<Boolean> func;
		
		public GemuScript(String n, Callable<Boolean> script)
		{
			name = n;
			func = script;
		}

		@Override
		public int compareTo(GemuScript o) {
			if(o == null) return -1;
			if(name == null) return -1;
			return name.compareTo(o.name);
		}
		@Override
		public int hashCode() {return name.hashCode();}
		@Override
		public String toString() {
			return name.toString();
		}
		@Override
		public boolean equals(Object o) {
			return name != null 
					&& o != null 
					&& ((GemuScript)o).name != null
					&& name.equals(((GemuScript)o).name);}
		
	}
	
	private void AddHook(Address addr2hook, GemuScript script) 
	{
		if(hookList == null) {
			hookList = new HashMap<Address, ArrayList<GemuScript>>();
		}

		ArrayList<GemuScript> scripts;
		gemu.setBreakpoint(addr2hook);
		if(hookList.containsKey(addr2hook)) 
		{
			scripts = hookList.get(addr2hook);
			scripts.add(script);
			hookList.put(addr2hook, scripts);
		} else {
			scripts = new ArrayList<GemuScript>();
			scripts.add(script);
			hookList.put(addr2hook, scripts);
		}
	}
	
	private boolean printState() {
		
		for(int i = 0; i < 12; i+=4) {
			printf("r%d= 0x%-10x r%d= 0x%-10x r%d= 0x%-10x r%d= 0x%-10x \n", 
					(i+0), gemu.readRegister("x"+(i+0)),
					(i+1), gemu.readRegister("x"+(i+1)),
					(i+2), gemu.readRegister("x"+(i+2)),
					(i+3), gemu.readRegister("x"+(i+3)));
		}
		printf("sp= 0x%-10x lr= 0x%-10x pc= 0x%-10x\n",
				gemu.readRegister("sp"),
				gemu.readRegister("x30"),
				gemu.readRegister("pc"));
		return true;
	}
	
	private boolean QuickReturn(int i){
		
		gemu.writeRegister("x0", i);
		gemu.writeRegister("pc", gemu.readRegister("x30").longValue());
		printState();
		return true;
	}

	private boolean printFunctionStart() {
		println(gemu.getExecutionAddress().toString() + " : " + getFunctionAt(gemu.getExecutionAddress()).toString() + " ");
		return true;
	}
	
	private boolean processBreakpointAndPatches(Address execAddr) throws Exception {

		ArrayList<GemuScript> scripts = hookList.get(execAddr);
		boolean ret = true;
		if(scripts != null){
			for(GemuScript g : scripts){
				ret &= g.func.call();
			}
		}
		// gemu.getEmulationExecutionState() == EmulateExecutionState.BREAKPOINT // for adding a debugger
		return ret; 

	}

	public class NopCallback extends BreakCallBack
	{
		public boolean pcodeCallback(PcodeOpRaw op){
			println("Unknown pcode: " + op.toString() + " :: " + op.getAddress().toString());
			return true;
		}
	}

}
